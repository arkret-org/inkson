//! Signal Extension sender surface (`spec/v1/zh/sync/signal.md`).
//!
//! v1 has exactly one Signal rail and it is encrypted-only. The plaintext
//! `EphemeralEnvelope` broadcast rail (`ak.typing` / `ak.presence` /
//! `ak.receipt.read` / `ak.call.signal` as bare wire objects on
//! `POST /_arkret/self/ephemeral`) no longer exists: the exact payload type,
//! the Strand / Message / Call / receipt target and the sender sequence live
//! inside `encrypted_payload` and are never reconstructible from the outer
//! header.
//!
//! What survives from the old rail is the *plaintext body* of each signal —
//! that body is now the AEAD plaintext instead of a wire object. This module
//! keeps those bodies, the header assembly and the device proof.

pub use arkret_sdk::SignalSequence;
use serde_json::Value;

/// Sender-side sequence within one `(scope_ref, sender_device_id)` stream.
///
/// The receiver dedupes on `(sender_device_id, scope_ref, payload_sequence)`
/// (`signal.md` §2). The sequence is inside the ciphertext, so a service can
/// only suppress replays by whole-envelope digest.
const SIGNAL_SEQUENCE_RESERVATION_BLOCK: u64 = 256;

#[derive(Clone, Copy, Debug)]
struct SignalSequenceReservation {
    next: u64,
    end_exclusive: u64,
}

fn signal_sequence_reservations()
-> &'static std::sync::Mutex<std::collections::BTreeMap<String, SignalSequenceReservation>> {
    static RESERVATIONS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, SignalSequenceReservation>>,
    > = std::sync::OnceLock::new();
    RESERVATIONS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

fn signal_sequence_domain(
    sender_device_id: &arkret_sdk::DeviceId,
    scope_ref: &arkret_sdk::ScopeRef,
) -> anyhow::Result<String> {
    use sha2::Digest as _;

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"ak.signal-sequence-domain-v1\0");
    transcript.extend_from_slice(sender_device_id.as_str().as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(&arkret_sdk::canonical::canonical_json_bytes(scope_ref)?);
    Ok(hex::encode(sha2::Sha256::digest(transcript)))
}

/// Consume a sequence from a durably reserved per-device/per-scope block.
///
/// The durable high-water is committed before the first number in a new block
/// is returned.  A crash may therefore burn the unused tail, which is valid;
/// no restart, failed submit, process, or browser tab can reuse it.
pub async fn next_signal_sequence(
    _state_store: &crate::runtime::input::StateStoreHandle,
    sender_device_id: &arkret_sdk::DeviceId,
    scope_ref: &arkret_sdk::ScopeRef,
) -> anyhow::Result<SignalSequence> {
    let domain = signal_sequence_domain(sender_device_id, scope_ref)?;
    let account_namespace = _state_store.read(|store| store.signal_sequence_store_namespace());
    let cached_domain = format!("{account_namespace}\0{domain}");
    {
        let mut reservations = signal_sequence_reservations()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(reservation) = reservations.get_mut(&cached_domain)
            && reservation.next < reservation.end_exclusive
        {
            let value = reservation.next;
            reservation.next += 1;
            return Ok(SignalSequence::new(value));
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    let first = {
        let path = _state_store.read(|store| store.signal_sequence_store_path());
        reserve_signal_sequence_block_in_file(&path, &domain, SIGNAL_SEQUENCE_RESERVATION_BLOCK)?
    };

    #[cfg(target_arch = "wasm32")]
    let first = reserve_signal_sequence_block_in_browser(
        &format!("inkson.signal_sequence.v1.{account_namespace}.{domain}"),
        SIGNAL_SEQUENCE_RESERVATION_BLOCK,
    )
    .await?;

    let end_exclusive = first
        .checked_add(SIGNAL_SEQUENCE_RESERVATION_BLOCK)
        .ok_or_else(|| anyhow::anyhow!("Signal payload_sequence exhausted"))?;
    let mut reservations = signal_sequence_reservations()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Another task may have installed a block while this task was reserving.
    // Consume that installed block in lock-acquisition order and burn this
    // redundant block; returning `first` here could emit a lower block after a
    // higher one and manufacture a receiver-visible rollback.
    if let Some(reservation) = reservations.get_mut(&cached_domain)
        && reservation.next < reservation.end_exclusive
    {
        let value = reservation.next;
        reservation.next += 1;
        return Ok(SignalSequence::new(value));
    }
    reservations.insert(
        cached_domain,
        SignalSequenceReservation {
            next: first + 1,
            end_exclusive,
        },
    );
    Ok(SignalSequence::new(first))
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(serde::Serialize, serde::Deserialize)]
struct SignalSequenceReservationRecord {
    version: u8,
    domain: String,
    next_unreserved: u64,
}

#[cfg(not(target_arch = "wasm32"))]
fn reserve_signal_sequence_block_in_file(
    path: &std::path::Path,
    domain: &str,
    block_size: u64,
) -> anyhow::Result<u64> {
    use std::io::{Read as _, Write as _};

    use fs2::FileExt as _;

    if block_size == 0 {
        anyhow::bail!("Signal sequence reservation block must be non-zero");
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    file.lock_exclusive()?;
    let result = (|| -> anyhow::Result<u64> {
        let mut journal = Vec::new();
        file.read_to_end(&mut journal)?;
        if !journal.is_empty() && !journal.ends_with(b"\n") {
            anyhow::bail!(
                "Signal sequence reservation journal {} has an incomplete tail; refusing to risk sequence reuse",
                path.display()
            );
        }
        let mut high_waters = std::collections::BTreeMap::new();
        for line in journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let record: SignalSequenceReservationRecord =
                serde_json::from_slice(line).map_err(|error| {
                    anyhow::anyhow!(
                        "Signal sequence reservation journal {} is corrupt: {error}",
                        path.display()
                    )
                })?;
            if record.version != 1 {
                anyhow::bail!(
                    "Signal sequence reservation journal {} has unsupported version {}",
                    path.display(),
                    record.version
                );
            }
            high_waters.insert(record.domain, record.next_unreserved);
        }
        let first = high_waters.get(domain).copied().unwrap_or(1);
        let next_unreserved = first
            .checked_add(block_size)
            .ok_or_else(|| anyhow::anyhow!("Signal payload_sequence exhausted"))?;
        let mut encoded = serde_json::to_vec(&SignalSequenceReservationRecord {
            version: 1,
            domain: domain.to_owned(),
            next_unreserved,
        })?;
        encoded.push(b'\n');
        file.write_all(&encoded)?;
        file.sync_all()?;
        Ok(first)
    })();
    let unlock = fs2::FileExt::unlock(&file);
    result.and_then(|value| {
        unlock?;
        Ok(value)
    })
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export async function reserveSignalSequenceBlock(key, blockSize) {
  if (!globalThis.navigator?.locks) {
    throw new Error("Web Locks API is required for atomic Signal sequence reservation");
  }
  return await globalThis.navigator.locks.request(key, {mode: "exclusive"}, async () => {
    const storage = globalThis.localStorage;
    if (!storage) throw new Error("localStorage is unavailable");
    const encoded = storage.getItem(key);
    const first = encoded === null ? 1n : BigInt(encoded);
    const next = first + BigInt(blockSize);
    if (next > 18446744073709551615n) throw new Error("Signal payload_sequence exhausted");
    storage.setItem(key, next.toString());
    return first.toString();
  });
}
"#)]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = reserveSignalSequenceBlock)]
    async fn reserve_signal_sequence_block_js(
        key: &str,
        block_size: u64,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
}

#[cfg(target_arch = "wasm32")]
async fn reserve_signal_sequence_block_in_browser(
    key: &str,
    block_size: u64,
) -> anyhow::Result<u64> {
    let value = reserve_signal_sequence_block_js(key, block_size)
        .await
        .map_err(|error| anyhow::anyhow!("reserve Signal sequence block: {error:?}"))?;
    value
        .as_string()
        .ok_or_else(|| anyhow::anyhow!("Signal sequence reservation returned a non-string"))?
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid Signal sequence reservation: {error}"))
}

/// Product payload carried inside a Signal's ciphertext.
///
/// The variants are exactly the four broadcast bodies the deleted plaintext
/// rail carried. None of this reaches the outer envelope: an implementation
/// that starts putting `signal_kind`, `strand_id` or `call_id` on the header
/// has reintroduced the metadata leak the Signal rail removed
/// (`signal.md` §6).
#[derive(Clone, Debug, PartialEq)]
pub enum SignalPayload {
    Typing {
        strand_id: arkret_sdk::StrandId,
        typing: bool,
    },
    Presence {
        state: String,
        status_message: Option<String>,
        last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    },
    ReadReceipt {
        strand_id: arkret_sdk::StrandId,
        event_id: arkret_sdk::EventId,
    },
    CallSignal {
        call_id: arkret_sdk::CallId,
        /// Per-call anti-rollback sequence, independent of the common Signal
        /// rail `payload_sequence`.
        seq: u64,
        signal: arkret_sdk::CallSignalData,
    },
    MessageStream(arkret_sdk::MessageStreamFrame),
}

impl SignalPayload {
    /// Server-visible classification. It is the ONLY product signal the outer
    /// envelope exposes, and it fixes the TTL ceiling
    /// (setup 120s / moderation 60s / session 30s).
    pub fn signal_class(&self) -> arkret_wire::SignalClass {
        match self {
            // Call setup wakes a device and establishes a live session.
            Self::CallSignal { signal, .. }
                if matches!(
                    signal.kind(),
                    arkret_sdk::CallSignalKind::Invite
                        | arkret_sdk::CallSignalKind::Answer
                        | arkret_sdk::CallSignalKind::FocusJoin
                ) =>
            {
                arkret_wire::SignalClass::Setup
            }
            Self::CallSignal { signal, .. }
                if signal.kind() == arkret_sdk::CallSignalKind::Moderation =>
            {
                arkret_wire::SignalClass::Moderation
            }
            _ => arkret_wire::SignalClass::Session,
        }
    }

    /// Product lifetime of this payload, never above its class ceiling.
    ///
    /// The receiver takes the earlier of the outer `expires_at` and
    /// `sent_at + ttl_ms`, so a payload that is only meaningful for a moment
    /// (a typing indicator) can expire well before the class ceiling without
    /// widening what the header discloses.
    pub fn ttl(&self) -> chrono::Duration {
        let ceiling = self.signal_class().max_ttl();
        let product = match self {
            // A typing indicator is stale almost immediately; the pre-v1 rail
            // used the same 5 seconds.
            Self::Typing { .. } => chrono::Duration::seconds(5),
            _ => ceiling,
        };
        product.min(ceiling)
    }

    /// Canonical AEAD plaintext for this payload.
    ///
    /// Every profile goes through the SDK's shared Signal plaintext entry
    /// (`sync/signal.md` §1.1): the strong type carries `kind` and
    /// `payload_sequence` by construction and [`arkret_sdk::seal_signal_plaintext`]
    /// is the only path to bytes. Nothing here serializes a type and then tops
    /// up the common minimum afterwards — that is exactly how a profile ends up
    /// emitting a body its own receiver cannot parse.
    pub fn to_plaintext(
        &self,
        actor_id: &arkret_sdk::Did,
        sequence: SignalSequence,
    ) -> anyhow::Result<Vec<u8>> {
        let plaintext = |result: Result<Vec<u8>, arkret_wire::Error>, what: &str| {
            result.map_err(|error| anyhow::anyhow!("{what} plaintext encoding failed: {error}"))
        };
        match self {
            Self::MessageStream(frame) => {
                let mut frame = frame.clone();
                match &mut frame {
                    arkret_sdk::MessageStreamFrame::Keyframe(value) => {
                        value.payload_sequence = sequence.get();
                    }
                    arkret_sdk::MessageStreamFrame::Delta(value) => {
                        value.payload_sequence = sequence.get();
                    }
                    arkret_sdk::MessageStreamFrame::Abort(value) => {
                        value.payload_sequence = sequence.get();
                    }
                }
                plaintext(arkret_sdk::seal_signal_plaintext(&frame), "message stream")
            }
            Self::CallSignal {
                call_id,
                seq,
                signal,
            } => {
                // `payload_sequence` and the per-call `seq` are independent axes;
                // this profile carries both and may omit neither.
                let payload = arkret_sdk::CallSignalPlaintext::new(
                    sequence.get(),
                    call_id.clone(),
                    *seq,
                    signal.clone(),
                )?;
                plaintext(arkret_sdk::seal_signal_plaintext(&payload), "call signal")
            }
            Self::Typing { strand_id, typing } => {
                let payload =
                    arkret_sdk::TypingPlaintext::new(sequence.get(), strand_id.clone(), *typing)
                        .map_err(|error| anyhow::anyhow!("typing plaintext rejected: {error}"))?
                        .with_ttl_ms(self.ttl_ms()?)
                        .map_err(|error| anyhow::anyhow!("typing ttl_ms rejected: {error}"))?;
                plaintext(arkret_sdk::seal_signal_plaintext(&payload), "typing")
            }
            Self::Presence {
                state,
                status_message,
                last_active_at,
            } => {
                let state: arkret_sdk::PresenceState =
                    serde_json::from_value(Value::String(state.clone())).map_err(|_| {
                        anyhow::anyhow!(
                            "presence state {state:?} is not a canonical presence state"
                        )
                    })?;
                let mut payload = arkret_sdk::PresencePlaintext::new(
                    sequence.get(),
                    actor_id.clone(),
                    state,
                    self.ttl_ms()?,
                )
                .map_err(|error| anyhow::anyhow!("presence plaintext rejected: {error}"))?;
                if let Some(message) = status_message
                    .as_deref()
                    .map(str::trim)
                    .filter(|message| !message.is_empty())
                {
                    // Sender-side fail-closed with the same constraint the
                    // receiver enforces (<=256 code points, NFC, no controls).
                    payload = payload
                        .with_status_message(arkret_sdk::canonical::to_nfc(message))
                        .map_err(|error| {
                            anyhow::anyhow!("presence status_message rejected: {error}")
                        })?;
                }
                if let Some(last_active_at) = last_active_at {
                    payload =
                        payload.with_last_active_at(bucket_presence_timestamp(*last_active_at));
                }
                plaintext(arkret_sdk::seal_signal_plaintext(&payload), "presence")
            }
            Self::ReadReceipt {
                strand_id,
                event_id,
            } => {
                // No `ttl_ms`: the read-receipt profile does not have one. The
                // envelope `expires_at` is already the TTL, and the closed
                // schema rejects the field outright.
                let receipt = arkret_sdk::ReadReceipt::new(
                    sequence.get(),
                    actor_id.clone(),
                    event_id.clone(),
                    arkret_sdk::ReadReceiptScope::strand(
                        strand_id.as_str().to_owned(),
                        Some("discussion"),
                    ),
                )
                .map_err(|error| anyhow::anyhow!("read receipt plaintext rejected: {error}"))?;
                plaintext(arkret_sdk::seal_signal_plaintext(&receipt), "read receipt")
            }
        }
    }

    /// Product TTL in milliseconds, for the profiles whose closed schema has a
    /// `ttl_ms` field.
    fn ttl_ms(&self) -> anyhow::Result<u64> {
        u64::try_from(self.ttl().num_milliseconds())
            .map_err(|_| anyhow::anyhow!("signal ttl does not fit a plaintext ttl_ms"))
    }
}

/// One-hour epoch-aligned `<start>/<end>` bucket for `last_active_at`.
///
/// `signal-presence.schema.json` requires both halves to be RFC 3339 instants —
/// an ISO 8601 duration on the right-hand side (`<start>/PT1H`) is not the
/// registered form and would be rejected as `schema_violation` by the receiver.
fn bucket_presence_timestamp(ts: chrono::DateTime<chrono::Utc>) -> String {
    const BUCKET_SECONDS: i64 = 60 * 60;
    let start_epoch = ts.timestamp() - ts.timestamp().rem_euclid(BUCKET_SECONDS);
    let stamp = |epoch: i64| {
        arkret_sdk::canonical::format_timestamp_canonical(
            chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0).unwrap_or(ts),
        )
    };
    format!(
        "{}/{}",
        stamp(start_epoch),
        stamp(start_epoch + BUCKET_SECONDS)
    )
}

/// Immutable server-visible header of a Signal, assembled before encryption.
///
/// `scope_ref` comes from the target's accepted projection, never from
/// user-supplied payload text, and `seal_ref` is the accepted Seal under which
/// the sending device's live-send eligibility is checked.
#[derive(Clone, Debug)]
pub struct SignalHeader {
    pub scope_ref: arkret_sdk::ScopeRef,
    pub sender_actor_id: arkret_sdk::Did,
    pub sender_device_id: arkret_sdk::DeviceId,
    pub seal_ref: arkret_sdk::SealId,
    pub signal_class: arkret_wire::SignalClass,
    pub sent_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl SignalHeader {
    /// Header at `sent_at` with the maximum TTL its class allows.
    pub fn new(
        scope_ref: arkret_sdk::ScopeRef,
        sender_actor_id: arkret_sdk::Did,
        sender_device_id: arkret_sdk::DeviceId,
        seal_ref: arkret_sdk::SealId,
        signal_class: arkret_wire::SignalClass,
        sent_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            scope_ref,
            sender_actor_id,
            sender_device_id,
            seal_ref,
            signal_class,
            sent_at,
            expires_at: sent_at + signal_class.max_ttl(),
        }
    }
}

/// The MLS group state a Signal's content key is exported from.
#[derive(Clone, Debug)]
pub struct SignalKeyMaterial {
    /// Accepted `ak.mls.genesis` / winning `ak.mls.commit` for the scope's
    /// group, or an equivalent group-state proof hash.
    pub group_state_ref: String,
    pub epoch: u64,
    /// `canonical_id` of the ACTIVE MLS ciphersuite the group at
    /// `group_state_ref` actually negotiated.
    pub aead_profile: String,
}

/// The single `status=active` MLS ciphersuite of the registry.
///
/// `aead_profile` MUST equal the suite the scope's group actually negotiated.
/// Every other registered suite is `reserved` behind a profile gate this client
/// does not enable, so a group it can restore locally can only have negotiated
/// this one; a future activation is picked up from the registry, not from a
/// literal here.
fn sole_active_mls_ciphersuite() -> Option<&'static str> {
    let mut active = arkret_sdk::MLS_CIPHERSUITES
        .iter()
        .filter(|suite| suite.status == "active");
    let first = active.next()?;
    active.next().is_none().then_some(first.canonical_id)
}

/// Resolve the Signal key material for `(realm_id, circle_id)` from accepted
/// local MLS state.
///
/// Fails closed when the scope has no accepted group state: v1 has no
/// plaintext branch to fall back to.
pub fn key_material_for_scope(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
) -> Result<SignalKeyMaterial, SignalRailUnavailable> {
    let unavailable = || SignalRailUnavailable {
        scope: match circle_id {
            Some(circle_id) => format!("{realm_id}/{circle_id}"),
            None => realm_id.to_owned(),
        },
    };
    let snapshot = state_store
        .mls_snapshot_for_effective_scope(realm_id, circle_id)
        .ok_or_else(unavailable)?;
    let group_state_ref = state_store
        .mls_group_state_ref_for_effective_scope(
            realm_id,
            circle_id,
            &snapshot.group_id,
            snapshot.epoch,
        )
        .map_err(|_| unavailable())?;
    Ok(SignalKeyMaterial {
        group_state_ref: group_state_ref.to_string(),
        epoch: snapshot.epoch,
        aead_profile: sole_active_mls_ciphersuite()
            .ok_or_else(unavailable)?
            .to_owned(),
    })
}

/// The Signal rail is unavailable for this scope.
///
/// `signal.md` §3 requires an implementation that cannot produce or verify
/// encrypted Signals for a scope to withdraw the scope capability rather than
/// fall back; there is no plaintext branch to fall back to.
#[derive(Debug, thiserror::Error)]
#[error(
    "signal rail unavailable for {scope}: sealing requires mutable persisted MLS \
     state and its account snapshot secret; v1 has no plaintext fallback"
)]
pub struct SignalRailUnavailable {
    pub scope: String,
}

/// The scope's persisted MLS group, restored at exactly one epoch.
///
/// Both Signal directions need this and neither may improvise it: the AEAD
/// content key is exported from the group at a single epoch, so opening or
/// sealing under any other epoch would use a key the scope has already rotated
/// away from.
pub struct SignalMlsSession {
    pub group: arkret_sdk::ArkretMlsGroup,
    pub snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    pub snapshot_secret: String,
}

/// Restore the scope's persisted MLS group and require it to sit at
/// `expected_epoch`.
///
/// Shared by the send path ([`encrypt_signal_payload_with_store`]) and the
/// receive path (`signal_receive_engine::MlsSignalDecryptor`) so the epoch gate
/// and the snapshot-secret lookup exist once. An epoch mismatch is fail-closed
/// on both sides: a Signal lives at most 120 seconds and the rail tolerates
/// loss by design (`signal.md` §4.5), so the straddling window is not worth
/// spending forward secrecy on.
pub fn restore_signal_mls_session(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    scope_ref: &arkret_sdk::ScopeRef,
    actor_id: &str,
    device_id: &str,
    expected_epoch: u64,
) -> anyhow::Result<SignalMlsSession> {
    let realm_id = scope_ref.realm_id().as_str();
    let circle_id = scope_ref.circle_id().map(arkret_sdk::CircleId::as_str);
    let snapshot = state_store
        .mls_snapshot_for_effective_scope(realm_id, circle_id)
        .ok_or_else(|| anyhow::anyhow!("no accepted MLS group state for the signal scope"))?;
    if snapshot.epoch != expected_epoch {
        anyhow::bail!(
            "signal names MLS epoch {expected_epoch}, but the scope is at epoch {}",
            snapshot.epoch
        );
    }
    let snapshot_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_id, device_id)
            .map_err(|error| anyhow::anyhow!("load Signal MLS snapshot secret: {error}"))?;
    let group =
        crate::mls::persistence::restore_envelope(&snapshot, &snapshot_secret, snapshot.epoch)
            .map_err(|error| anyhow::anyhow!("restore Signal MLS snapshot: {error}"))?;
    Ok(SignalMlsSession {
        group,
        snapshot,
        snapshot_secret,
    })
}

/// Seal a Signal and durably burn the SDK-owned nonce counter before submit.
pub fn encrypt_signal_payload_with_store(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    header: &SignalHeader,
    material: &SignalKeyMaterial,
    plaintext: &[u8],
) -> anyhow::Result<arkret_wire::SignalEncryptedPayload> {
    let realm_id = header.scope_ref.realm_id().as_str();
    let circle_id = header
        .scope_ref
        .circle_id()
        .map(arkret_sdk::CircleId::as_str);
    let SignalMlsSession {
        mut group,
        snapshot,
        snapshot_secret,
    } = restore_signal_mls_session(
        state_store,
        secure_store,
        &header.scope_ref,
        header.sender_actor_id.as_str(),
        header.sender_device_id.as_str(),
        material.epoch,
    )?;
    let key_ref = arkret_wire::SignalKeyRef {
        algorithm: "MLS-EXPORTER-AEAD".to_owned(),
        group_state_ref: material.group_state_ref.clone(),
    };
    let binding = arkret_wire::SignalAeadBinding {
        realm_id: header.scope_ref.realm_id(),
        scope_ref: &header.scope_ref,
        sender_actor_id: &header.sender_actor_id,
        sender_device_id: &header.sender_device_id,
        seal_ref: &header.seal_ref,
        signal_class: header.signal_class,
        sent_at: header.sent_at,
        expires_at: header.expires_at,
        scheme: arkret_wire::signal::SIGNAL_AEAD_SCHEME,
        key_ref: &key_ref,
        purpose: arkret_wire::signal::SIGNAL_AEAD_PURPOSE,
        aead_profile: &material.aead_profile,
        epoch: material.epoch,
    };
    let sealed = group
        .seal_signal_payload(&binding, plaintext)
        .map_err(|error| anyhow::anyhow!("seal Signal payload: {error}"))?;

    // Persist before the HTTP submit. A failed or uncertain request may skip a
    // nonce value, but it must never allow that value to be reused.
    let state = group
        .export_state_record()
        .map_err(|error| anyhow::anyhow!("export post-Signal MLS state: {error}"))?;
    let state_bytes = serde_json::to_vec(&state)
        .map_err(|error| anyhow::anyhow!("serialize post-Signal MLS state: {error}"))?;
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow::anyhow!("generate Signal snapshot salt: {error}"))?;
    let updated = crate::mls::persistence::encrypt_state(
        realm_id,
        &state.group_id,
        state.epoch,
        &state_bytes,
        &snapshot_secret,
        &salt,
    )
    .carry_epoch_started_at(&snapshot)
    .with_app_messages_observed(snapshot.app_messages_observed);
    state_store.save_mls_snapshot_for_effective_scope(realm_id.to_owned(), circle_id, updated);
    Ok(sealed.encrypted_payload)
}

/// Assemble the complete envelope and attach the sending device's proof.
///
/// `aad_digest` is recomputed from the assembled header and must byte-equal
/// what the AEAD was run with; `envelope_digest` then covers everything except
/// the proof, so it commits to the ciphertext and the AAD binding as well.
pub fn seal_signal_envelope(
    header: SignalHeader,
    encrypted_payload: arkret_wire::SignalEncryptedPayload,
) -> anyhow::Result<arkret_wire::SignalEnvelope> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("no active signer configured — cannot send a Signal without a device proof")
    })?;
    let verification_method = arkret_sdk::DidUrl::new(format!(
        "{}#{}",
        header.sender_actor_id, header.sender_device_id
    ))
    .map_err(|error| anyhow::anyhow!("signal proof verification method is invalid: {error}"))?;
    let mut envelope = arkret_wire::SignalEnvelope {
        realm_id: header.scope_ref.realm_id().clone(),
        scope_ref: header.scope_ref,
        sender_actor_id: header.sender_actor_id,
        sender_device_id: header.sender_device_id,
        seal_ref: header.seal_ref,
        signal_class: header.signal_class,
        sent_at: header.sent_at,
        expires_at: header.expires_at,
        encrypted_payload,
        proof: arkret_wire::SignalProof {
            kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: verification_method.clone(),
            envelope_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            // `signal.md` §1: proof created_at MUST equal the outer sent_at.
            created_at: header.sent_at,
            domain: None,
            audience: None,
            jws: String::new(),
        },
    };
    let expected_aad = envelope
        .expected_aad_digest()
        .map_err(|error| anyhow::anyhow!("signal AAD digest recomputation failed: {error}"))?;
    if envelope.encrypted_payload.aad_digest != expected_aad {
        anyhow::bail!("signal ciphertext was sealed against a different header");
    }
    envelope.proof.envelope_digest = envelope
        .envelope_digest()
        .map_err(|error| anyhow::anyhow!("signal envelope digest failed: {error}"))?;
    let binding_bytes = envelope
        .proof_binding_bytes()
        .map_err(|error| anyhow::anyhow!("signal proof transcript failed: {error}"))?;
    envelope.proof.jws = signer
        .detached_jws_over(&binding_bytes)
        .map_err(|error| anyhow::anyhow!("signal proof signing failed: {error}"))?;
    envelope
        .validate_structural()
        .map_err(|error| anyhow::anyhow!("assembled signal envelope is invalid: {error}"))?;
    Ok(envelope)
}

/// Envelope fixtures for the receive-side tests of other modules.
///
/// Sealing a real Signal needs mutable persisted MLS state and its account
/// snapshot secret ([`encrypt_signal_payload_with_store`]), which a unit test
/// of a receive path does not have. These helpers therefore supply opaque
/// ciphertext and let [`seal_signal_envelope`] recompute the AAD binding, the
/// envelope digest and the device proof exactly as production does. Only the
/// AEAD body is fake; every field a receiver checks is real.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Ciphertext stand-in bound to `header`, ready for
    /// [`seal_signal_envelope`].
    pub(crate) fn opaque_encrypted_payload(
        header: &SignalHeader,
    ) -> arkret_wire::SignalEncryptedPayload {
        let mut encrypted = arkret_wire::SignalEncryptedPayload {
            scheme: arkret_wire::signal::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: arkret_wire::SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:AZVgkcivLIz2PjwUcjuT5bTb6295nnowDbSQak0QfNCa".to_owned(),
            },
            purpose: arkret_wire::signal::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 4,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            aad_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        };
        let probe = arkret_wire::SignalEnvelope {
            realm_id: header.scope_ref.realm_id().clone(),
            scope_ref: header.scope_ref.clone(),
            sender_actor_id: header.sender_actor_id.clone(),
            sender_device_id: header.sender_device_id.clone(),
            seal_ref: header.seal_ref.clone(),
            signal_class: header.signal_class,
            sent_at: header.sent_at,
            expires_at: header.expires_at,
            encrypted_payload: encrypted.clone(),
            proof: arkret_wire::SignalProof {
                kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_sdk::DidUrl::new(format!(
                    "{}#{}",
                    header.sender_actor_id, header.sender_device_id
                ))
                .unwrap(),
                envelope_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at: header.sent_at,
                domain: None,
                audience: None,
                jws: String::new(),
            },
        };
        encrypted.aad_digest = probe.expected_aad_digest().unwrap();
        encrypted
    }

    /// A fully signed envelope plus the plaintext body a receiver would get
    /// out of it. Requires an installed active signer for `actor#device`.
    pub(crate) fn sealed_signal(
        payload: &SignalPayload,
        realm_id: &arkret_sdk::RealmId,
        actor_id: &arkret_sdk::Did,
        device_id: &arkret_sdk::DeviceId,
        sequence: SignalSequence,
    ) -> anyhow::Result<(arkret_wire::SignalEnvelope, Value)> {
        let sent_at = crate::clock::now_utc();
        let header = SignalHeader::new(
            arkret_sdk::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_id.clone(),
            device_id.clone(),
            arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "ab".repeat(32)))?,
            payload.signal_class(),
            sent_at,
        );
        let plaintext = payload.to_plaintext(actor_id, sequence)?;
        let encrypted = opaque_encrypted_payload(&header);
        let envelope = seal_signal_envelope(header, encrypted)?;
        Ok((envelope, serde_json::from_slice(&plaintext)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn realm() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new("ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j").unwrap()
    }

    fn actor() -> arkret_sdk::Did {
        arkret_sdk::Did::new("did:web:alice.example").unwrap()
    }

    /// The deleted plaintext rail put `typing` / `strand_id` / `track_name` on
    /// the wire header. They are now AEAD plaintext, so the assertion moves to
    /// the plaintext body and additionally pins that the body carries the
    /// dedupe sequence a receiver needs.
    #[test]
    fn typing_body_is_ciphertext_content_not_header_metadata() {
        let payload = SignalPayload::Typing {
            strand_id: arkret_sdk::StrandId::new(
                "ak:strand:Aa6k_ga4nHTT-mJwrlDP8oeaq3P1Wg9B6K8RtTXZyUY0".to_owned(),
            )
            .unwrap(),
            typing: true,
        };
        let plaintext = payload
            .to_plaintext(&actor(), SignalSequence::new(7))
            .unwrap();
        let body: Value = serde_json::from_slice(&plaintext).unwrap();

        assert_eq!(body["kind"], "ak.typing");
        assert_eq!(
            body["strand_id"],
            "ak:strand:Aa6k_ga4nHTT-mJwrlDP8oeaq3P1Wg9B6K8RtTXZyUY0"
        );
        // `track_name` is optional on the wire and an absent value resolves to
        // `discussion` on the receiver, so a sender that does not select a
        // track MUST NOT spell the default out.
        assert!(body.get("track_name").is_none());
        assert_eq!(body["typing"], true);
        assert_eq!(body["payload_sequence"], 7);
        // Typing is an ordinary session signal: the 30 second class ceiling.
        assert_eq!(payload.signal_class(), arkret_wire::SignalClass::Session);
        assert_eq!(payload.signal_class().max_ttl().num_seconds(), 30);
    }

    #[test]
    fn message_stream_uses_its_closed_profile_plaintext() {
        let frame = arkret_sdk::MessageStreamFrame::Keyframe(
            arkret_sdk::MessageStreamKeyframe::new(
                999,
                arkret_sdk::StrandId::new("ak:strand:Aa6k_ga4nHTT-mJwrlDP8oeaq3P1Wg9B6K8RtTXZyUY0")
                    .unwrap(),
                arkret_sdk::MessageId::new(
                    "ak:message:AdivMIiemZ8QCSxNhw_XxuE2l2aHRyO5pQ9NSob7hLEO",
                )
                .unwrap(),
                0,
                arkret_sdk::MessageStreamId::new(
                    "ak:message_stream:01964200-0000-7000-8000-000000000003",
                )
                .unwrap(),
                0,
                arkret_sdk::MessageStreamFormat::Markdown,
                "draft",
                false,
            )
            .unwrap(),
        );
        let body: Value = serde_json::from_slice(
            &SignalPayload::MessageStream(frame)
                .to_plaintext(&actor(), SignalSequence::new(8))
                .unwrap(),
        )
        .unwrap();

        assert_eq!(body["kind"], "ak.message.stream");
        assert_eq!(body["payload_sequence"], 8);
        assert!(body.get("actor_id").is_none());
        assert!(body.get("ttl_ms").is_none());
    }

    #[test]
    fn presence_body_rejects_non_canonical_state_and_buckets_last_active_at() {
        let bad = SignalPayload::Presence {
            state: "invisible".to_owned(),
            status_message: None,
            last_active_at: None,
        };
        assert!(bad.to_plaintext(&actor(), SignalSequence::new(0)).is_err());

        let payload = SignalPayload::Presence {
            state: "online".to_owned(),
            status_message: Some("  hi  ".to_owned()),
            last_active_at: Some(
                chrono::DateTime::parse_from_rfc3339("2026-05-19T12:34:56Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
        };
        let body: Value = serde_json::from_slice(
            &payload
                .to_plaintext(&actor(), SignalSequence::new(1))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["state"], "online");
        assert_eq!(body["status_message"], "hi");
        // `<start>/<end>`, both RFC 3339 instants: the schema does not accept
        // an ISO 8601 duration on the right-hand side.
        assert_eq!(
            body["last_active_at"],
            "2026-05-19T12:00:00.000Z/2026-05-19T13:00:00.000Z"
        );
    }

    #[test]
    fn read_receipt_body_carries_the_canonical_receipt_object() {
        let payload = SignalPayload::ReadReceipt {
            strand_id: arkret_sdk::StrandId::new(
                "ak:strand:Aa6k_ga4nHTT-mJwrlDP8oeaq3P1Wg9B6K8RtTXZyUY0".to_owned(),
            )
            .unwrap(),
            event_id: arkret_sdk::EventId::new(
                "ak:event:AdivMIiemZ8QCSxNhw_XxuE2l2aHRyO5pQ9NSob7hLEO",
            )
            .unwrap(),
        };
        let body: Value = serde_json::from_slice(
            &payload
                .to_plaintext(&actor(), SignalSequence::new(2))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["kind"], "ak.receipt.read");
        assert_eq!(body["payload_sequence"], 2);
        // The durable-object leftovers are gone: the receipt is a Signal
        // plaintext, so it restates neither the Realm nor the send time, and
        // has no `receipt_kind` / `schema` / `created_at`.
        for retired in ["receipt_kind", "schema", "realm_id", "created_at", "ttl_ms"] {
            assert!(
                body.get(retired).is_none(),
                "read receipt plaintext must not carry '{retired}': {body}"
            );
        }
        // `ReadReceiptScope` single-sources its target through `object_ref`.
        assert_eq!(body["read_scope"]["kind"], "strand");
        assert_eq!(
            body["read_scope"]["object_ref"],
            "ak:strand:Aa6k_ga4nHTT-mJwrlDP8oeaq3P1Wg9B6K8RtTXZyUY0"
        );
        assert_eq!(body["read_scope"]["track_name"], "discussion");
    }

    #[test]
    fn call_signal_type_drives_the_class_ceiling() {
        let call_id =
            arkret_sdk::CallId::new("ak:call:AV2POYJXMfLYPg5u4jsNfpIyQjrEWx4_pWcsA9U7yXJQ")
                .unwrap();
        let invite = SignalPayload::CallSignal {
            call_id: call_id.clone(),
            seq: 4,
            signal: arkret_sdk::CallSignalData::Invite(arkret_sdk::CallInviteSignalData {
                lifetime_ms: 60_000,
                mode: arkret_sdk::CallMode::P2p,
                offer: arkret_sdk::SessionDescription {
                    sdp_type: arkret_sdk::SessionDescriptionType::Offer,
                    sdp: "v=0".to_owned(),
                },
                media: arkret_sdk::CallMediaSelection {
                    audio: true,
                    video: true,
                    screen: Some(false),
                },
            }),
        };
        assert_eq!(invite.signal_class(), arkret_wire::SignalClass::Setup);
        assert_eq!(invite.signal_class().max_ttl().num_seconds(), 120);

        let moderation = SignalPayload::CallSignal {
            call_id: call_id.clone(),
            seq: 5,
            signal: arkret_sdk::CallSignalData::Moderation(arkret_sdk::CallModerationSignalData {
                action: arkret_sdk::CallModerationAction::EndForAll,
                target_actor_id: None,
                target_device_id: None,
                reason: None,
            }),
        };
        assert_eq!(
            moderation.signal_class(),
            arkret_wire::SignalClass::Moderation
        );
        assert_eq!(moderation.signal_class().max_ttl().num_seconds(), 60);

        let candidate = SignalPayload::CallSignal {
            call_id,
            seq: 6,
            signal: arkret_sdk::CallSignalData::Candidate(arkret_sdk::CallCandidateSignalData {
                candidates: vec![arkret_sdk::IceCandidate {
                    candidate: "candidate:1".to_owned(),
                    sdp_mid: Some("0".to_owned()),
                    sdp_m_line_index: Some(0),
                }],
            }),
        };
        assert_eq!(candidate.signal_class(), arkret_wire::SignalClass::Session);
        let body: Value = serde_json::from_slice(
            &candidate
                .to_plaintext(&actor(), SignalSequence::new(1024))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["payload_sequence"], 1024);
        assert_eq!(body["seq"], 6, "per-call seq is an independent axis");
    }

    /// Restates the deleted `presence_proof_round_trips_through_ephemeral_sdk_verifier`
    /// test. The plaintext ephemeral binding context is gone; the v1 transcript
    /// is `ak.signal-proof-v1` over `envelope_digest` plus the sender binding,
    /// with `proof.created_at` byte-equal to the header `sent_at`.
    ///
    /// The ciphertext here is opaque filler: this asserts the proof transcript
    /// and the AAD-to-header binding, neither of which depends on the AEAD.
    #[test]
    fn signal_proof_binds_the_header_and_verifies_under_the_device_key() {
        use std::sync::Arc;

        use arkret_sdk::signatures::PublicKeyMaterial;
        use ed25519_dalek::SigningKey;

        use crate::event_signer::{ActiveSignerTestGuard, build_ed25519_device_signer};

        let seed = [15u8; 32];
        let actor_id = "did:web:alice.example";
        let device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
        let signer = Arc::new(build_ed25519_device_signer(seed, actor_id, device_id));
        let _guard = ActiveSignerTestGuard::replace(Some(signer));

        let header = SignalHeader::new(
            arkret_sdk::ScopeRef::Realm { realm_id: realm() },
            actor(),
            arkret_sdk::DeviceId::new(device_id).unwrap(),
            arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "ab".repeat(32))).unwrap(),
            arkret_wire::SignalClass::Session,
            crate::clock::now_utc(),
        );
        let mut encrypted = arkret_wire::SignalEncryptedPayload {
            scheme: arkret_wire::signal::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: arkret_wire::SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:AZVgkcivLIz2PjwUcjuT5bTb6295nnowDbSQak0QfNCa".to_owned(),
            },
            purpose: arkret_wire::signal::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 4,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            aad_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        };
        // Recompute the AAD digest the way a receiver does, from the header.
        let probe = arkret_wire::SignalEnvelope {
            realm_id: header.scope_ref.realm_id().clone(),
            scope_ref: header.scope_ref.clone(),
            sender_actor_id: header.sender_actor_id.clone(),
            sender_device_id: header.sender_device_id.clone(),
            seal_ref: header.seal_ref.clone(),
            signal_class: header.signal_class,
            sent_at: header.sent_at,
            expires_at: header.expires_at,
            encrypted_payload: encrypted.clone(),
            proof: arkret_wire::SignalProof {
                kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_sdk::DidUrl::new(format!("{actor_id}#{device_id}"))
                    .unwrap(),
                envelope_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at: header.sent_at,
                domain: None,
                audience: None,
                jws: String::new(),
            },
        };
        encrypted.aad_digest = probe.expected_aad_digest().unwrap();

        let envelope = seal_signal_envelope(header, encrypted).unwrap();
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        assert!(
            crate::identity::device_directory::verify_signal_envelope_proof(&envelope, &public_key)
        );

        // Rewriting any header member breaks the AAD binding, so the sealer
        // refuses to mint a proof over ciphertext sealed for another header.
        let mut tampered = envelope.clone();
        tampered.signal_class = arkret_wire::SignalClass::Setup;
        assert!(
            !crate::identity::device_directory::verify_signal_envelope_proof(
                &tampered,
                &public_key
            )
        );
    }

    #[test]
    fn presence_status_message_over_the_wire_limit_fails_closed() {
        let payload = SignalPayload::Presence {
            state: "dnd".to_owned(),
            status_message: Some("字".repeat(257)),
            last_active_at: None,
        };
        assert!(
            payload
                .to_plaintext(&actor(), SignalSequence::new(0))
                .is_err()
        );
    }

    #[test]
    fn header_ttl_follows_the_class_ceiling() {
        let sent_at = crate::clock::now_utc();
        for (class, seconds) in [
            (arkret_wire::SignalClass::Setup, 120),
            (arkret_wire::SignalClass::Moderation, 60),
            (arkret_wire::SignalClass::Session, 30),
        ] {
            let header = SignalHeader::new(
                arkret_sdk::ScopeRef::Realm { realm_id: realm() },
                actor(),
                arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-a11ce0000001")
                    .unwrap(),
                arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "ab".repeat(32))).unwrap(),
                class,
                sent_at,
            );
            assert_eq!(
                (header.expires_at - header.sent_at).num_seconds(),
                seconds,
                "{class:?} TTL"
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn durable_sequence_reservations_survive_restart_and_allow_crash_gaps() {
        let dir = std::env::temp_dir().join(format!(
            "inkson-signal-sequence-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("high-water.json");

        // Simulate a process that reserves a block and crashes without using
        // its tail. The reopened allocator must skip that tail permanently.
        assert_eq!(
            reserve_signal_sequence_block_in_file(&path, "device-a/scope-a", 256).unwrap(),
            1
        );
        assert_eq!(
            reserve_signal_sequence_block_in_file(&path, "device-a/scope-a", 256).unwrap(),
            257
        );
        // A different scope owns an independent high-water domain.
        assert_eq!(
            reserve_signal_sequence_block_in_file(&path, "device-a/scope-b", 256).unwrap(),
            1
        );

        // An interrupted append cannot erase earlier committed records. Its
        // incomplete tail makes the allocator fail closed instead of guessing
        // a lower high-water and reusing a sequence.
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(br#"{"version":1"#)
            .unwrap();
        let error =
            reserve_signal_sequence_block_in_file(&path, "device-a/scope-a", 256).unwrap_err();
        assert!(error.to_string().contains("incomplete tail"));

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn concurrent_process_style_reservations_never_overlap() {
        let dir = std::env::temp_dir().join(format!(
            "inkson-signal-sequence-concurrent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("high-water.json");
        let mut threads = Vec::new();
        for _ in 0..8 {
            let path = path.clone();
            threads.push(std::thread::spawn(move || {
                reserve_signal_sequence_block_in_file(&path, "shared-domain", 32).unwrap()
            }));
        }
        let mut starts: Vec<u64> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        starts.sort_unstable();
        assert_eq!(starts, vec![1, 33, 65, 97, 129, 161, 193, 225]);

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
