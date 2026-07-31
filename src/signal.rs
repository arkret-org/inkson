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

use serde::Serialize;
use serde_json::{Value, json};

/// Sender-side sequence within one `(scope_ref, sender_device_id)` stream.
///
/// The receiver dedupes on `(sender_device_id, scope_ref, payload_sequence)`
/// (`signal.md` §2). The sequence is inside the ciphertext, so a service can
/// only suppress replays by whole-envelope digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SignalSequence(pub u64);

static SIGNAL_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Next per-process Signal sequence.
///
/// This covers the in-ciphertext `payload_sequence` a receiver dedupes on.
/// The AEAD `device_nonce_counter` has a stricter contract — `encoding.md`
/// §10.1 requires it to be persisted per `(key_ref, epoch, device_id, purpose,
/// aead_profile)` and, when the local counter for an epoch cannot be recovered,
/// requires an MLS Commit to a fresh epoch before sending again. The SDK owns
/// that counter inside the persisted MLS group snapshot.
pub fn next_signal_sequence() -> SignalSequence {
    SignalSequence(SIGNAL_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
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
        signal_kind: String,
        data: Option<Value>,
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
            Self::CallSignal { signal_kind, .. }
                if matches!(signal_kind.as_str(), "invite" | "answer" | "focus_join") =>
            {
                arkret_wire::SignalClass::Setup
            }
            Self::CallSignal { signal_kind, .. } if signal_kind == "moderation" => {
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
    /// `kind`, `actor_id`, `payload_sequence` and `ttl_ms` are the closed
    /// minimum every Signal plaintext carries — the shape
    /// [`garth::SignalPlaintext`] parses on the receive side. They are
    /// plaintext because the receiver dispatches on them after decryption;
    /// they were header fields on the deleted rail and MUST NOT go back there.
    pub fn to_plaintext(
        &self,
        actor_id: &arkret_sdk::Did,
        realm_id: &arkret_sdk::RealmId,
        sequence: SignalSequence,
        sent_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Vec<u8>> {
        if let Self::MessageStream(frame) = self {
            if frame.payload_sequence() != sequence.0 {
                anyhow::bail!(
                    "message stream payload_sequence {} disagrees with Signal sequence {}",
                    frame.payload_sequence(),
                    sequence.0
                );
            }
            return frame.canonical_plaintext().map_err(|error| {
                anyhow::anyhow!("message stream plaintext encoding failed: {error}")
            });
        }
        if let Self::CallSignal {
            call_id,
            signal_kind,
            data,
        } = self
        {
            let signal_kind: arkret_sdk::CallSignalKind =
                serde_json::from_value(Value::String(signal_kind.clone())).map_err(|_| {
                    anyhow::anyhow!(
                        "call signal_kind {:?} is not in the canonical enum",
                        signal_kind
                    )
                })?;
            let data = data
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("call signal data is required"))?
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("call signal data must be an object"))?
                .clone()
                .into_iter()
                .collect();
            return arkret_sdk::CallSignalPlaintext::new(
                call_id.clone(),
                signal_kind,
                sequence.0,
                data,
            )
            .canonical_plaintext()
            .map_err(|error| anyhow::anyhow!("call signal plaintext encoding failed: {error}"));
        }
        let body = match self {
            Self::Typing { strand_id, typing } => json!({
                "kind": "ak.typing",
                "strand_id": strand_id.as_str(),
                // The discussion track is the only writable Message timeline in v1.
                "track_name": "discussion",
                "typing": typing,
            }),
            Self::Presence {
                state,
                status_message,
                last_active_at,
            } => {
                if arkret_sdk::PresenceStatus::parse_wire(state).is_none() {
                    anyhow::bail!("presence state {state:?} is not a canonical presence state");
                }
                let mut body = json!({
                    "kind": "ak.presence",
                    "state": state,
                });
                if let Some(message) = status_message
                    .as_deref()
                    .map(str::trim)
                    .filter(|message| !message.is_empty())
                {
                    // Sender-side fail-closed with the same constraint the
                    // receiver enforces (<=256 code points, NFC, no controls).
                    let message = arkret_sdk::canonical::to_nfc(message);
                    arkret_sdk::validate_status_message(&message).map_err(|err| {
                        anyhow::anyhow!("presence status_message rejected: {err}")
                    })?;
                    body["status_message"] = Value::String(message);
                }
                if let Some(last_active_at) = last_active_at {
                    body["last_active_at"] =
                        Value::String(bucket_presence_timestamp(*last_active_at));
                }
                body
            }
            Self::ReadReceipt {
                strand_id,
                event_id,
            } => {
                let receipt = arkret_sdk::ReadReceipt {
                    receipt_kind: "read".to_owned(),
                    schema: arkret_sdk::READ_RECEIPT_SCHEMA.to_owned(),
                    realm_id: realm_id.clone(),
                    actor_id: actor_id.clone(),
                    event_id: event_id.clone(),
                    hlc: None,
                    read_scope: arkret_sdk::ReadReceiptScope::strand(
                        strand_id.as_str().to_owned(),
                        Some("discussion"),
                    ),
                    created_at: sent_at,
                };
                let mut body = serde_json::to_value(&receipt)?;
                body["kind"] = Value::String("ak.receipt.read".to_owned());
                body
            }
            Self::CallSignal { .. } => unreachable!("handled by the SDK closed call shape"),
            Self::MessageStream(_) => unreachable!("handled before generic Signal encoding"),
        };
        let mut body = body;
        body["actor_id"] = Value::String(actor_id.as_str().to_owned());
        body["payload_sequence"] = json!(sequence.0);
        body["ttl_ms"] = json!(self.ttl().num_milliseconds());
        let bytes = arkret_sdk::canonical::canonical_json_bytes(&body)
            .map_err(|error| anyhow::anyhow!("signal plaintext encoding failed: {error}"))?;
        if bytes.len() > arkret_wire::signal::MAX_SIGNAL_PLAINTEXT_BYTES {
            anyhow::bail!(
                "signal plaintext is {} bytes, over the {} byte ceiling",
                bytes.len(),
                arkret_wire::signal::MAX_SIGNAL_PLAINTEXT_BYTES
            );
        }
        Ok(bytes)
    }
}

fn bucket_presence_timestamp(ts: chrono::DateTime<chrono::Utc>) -> String {
    let bucketed = ts.timestamp() - ts.timestamp().rem_euclid(60 * 60);
    let start = arkret_sdk::canonical::format_timestamp_canonical(
        chrono::DateTime::<chrono::Utc>::from_timestamp(bucketed, 0).unwrap_or(ts),
    );
    format!("{start}/PT1H")
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
    /// Monotonic per-`(key_ref, epoch, device_id, purpose, aead_profile)`
    /// counter, the low 8 bytes of the canonical AEAD nonce.
    pub device_nonce_counter: u64,
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
    device_nonce_counter: u64,
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
        device_nonce_counter,
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
    let snapshot = state_store
        .mls_snapshot_for_effective_scope(realm_id, circle_id)
        .ok_or_else(|| anyhow::anyhow!("no MLS snapshot for Signal scope"))?;
    if snapshot.epoch != material.epoch {
        anyhow::bail!(
            "Signal material epoch {} disagrees with persisted MLS epoch {}",
            material.epoch,
            snapshot.epoch
        );
    }
    let snapshot_secret = crate::mls::runtime::load_device_snapshot_secret(
        secure_store,
        header.sender_actor_id.as_str(),
        header.sender_device_id.as_str(),
    )
    .map_err(|error| anyhow::anyhow!("load Signal MLS snapshot secret: {error}"))?;
    let mut group =
        crate::mls::persistence::restore_envelope(&snapshot, &snapshot_secret, snapshot.epoch)
            .map_err(|error| anyhow::anyhow!("restore Signal MLS snapshot: {error}"))?;
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
            alg: signer.algorithm().to_owned(),
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
                group_state_ref: "ak:event:01964200-0000-7000-8000-000000000004".to_owned(),
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
                alg: "EdDSA".to_owned(),
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
        let plaintext = payload.to_plaintext(actor_id, realm_id, sequence, sent_at)?;
        let encrypted = opaque_encrypted_payload(&header);
        let envelope = seal_signal_envelope(header, encrypted)?;
        Ok((envelope, serde_json::from_slice(&plaintext)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000000").unwrap()
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
                "ak:strand:01964200-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            typing: true,
        };
        let plaintext = payload
            .to_plaintext(
                &actor(),
                &realm(),
                SignalSequence(7),
                crate::clock::now_utc(),
            )
            .unwrap();
        let body: Value = serde_json::from_slice(&plaintext).unwrap();

        assert_eq!(body["kind"], "ak.typing");
        assert_eq!(
            body["strand_id"],
            "ak:strand:01964200-0000-7000-8000-000000000001"
        );
        assert_eq!(body["track_name"], "discussion");
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
                8,
                arkret_sdk::StrandId::new("ak:strand:01964200-0000-7000-8000-000000000001")
                    .unwrap(),
                arkret_sdk::MessageId::new("ak:message:01964200-0000-7000-8000-000000000002")
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
                .to_plaintext(
                    &actor(),
                    &realm(),
                    SignalSequence(8),
                    crate::clock::now_utc(),
                )
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
        assert!(
            bad.to_plaintext(
                &actor(),
                &realm(),
                SignalSequence(0),
                crate::clock::now_utc()
            )
            .is_err()
        );

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
                .to_plaintext(
                    &actor(),
                    &realm(),
                    SignalSequence(1),
                    crate::clock::now_utc(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["state"], "online");
        assert_eq!(body["status_message"], "hi");
        assert_eq!(body["last_active_at"], "2026-05-19T12:00:00.000Z/PT1H");
    }

    #[test]
    fn read_receipt_body_carries_the_canonical_receipt_object() {
        let payload = SignalPayload::ReadReceipt {
            strand_id: arkret_sdk::StrandId::new(
                "ak:strand:01964200-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            event_id: arkret_sdk::EventId::new("ak:event:01964200-0000-7000-8000-000000000002")
                .unwrap(),
        };
        let body: Value = serde_json::from_slice(
            &payload
                .to_plaintext(
                    &actor(),
                    &realm(),
                    SignalSequence(2),
                    crate::clock::now_utc(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["kind"], "ak.receipt.read");
        assert_eq!(body["receipt_kind"], "read");
        // `ReadReceiptScope` single-sources its target through `object_ref`.
        assert_eq!(body["read_scope"]["kind"], "strand");
        assert_eq!(
            body["read_scope"]["object_ref"],
            "ak:strand:01964200-0000-7000-8000-000000000001"
        );
        assert_eq!(body["read_scope"]["track_name"], "discussion");
    }

    #[test]
    fn call_signal_kind_is_checked_and_drives_the_class_ceiling() {
        let call_id =
            arkret_sdk::CallId::new("ak:call:01964200-0000-7000-8000-000000000003").unwrap();
        let rejected = SignalPayload::CallSignal {
            call_id: call_id.clone(),
            signal_kind: "not_a_kind".to_owned(),
            data: None,
        };
        assert!(
            rejected
                .to_plaintext(
                    &actor(),
                    &realm(),
                    SignalSequence(3),
                    crate::clock::now_utc()
                )
                .is_err()
        );

        let invite = SignalPayload::CallSignal {
            call_id: call_id.clone(),
            signal_kind: "invite".to_owned(),
            data: None,
        };
        assert_eq!(invite.signal_class(), arkret_wire::SignalClass::Setup);
        assert_eq!(invite.signal_class().max_ttl().num_seconds(), 120);

        let moderation = SignalPayload::CallSignal {
            call_id: call_id.clone(),
            signal_kind: "moderation".to_owned(),
            data: None,
        };
        assert_eq!(
            moderation.signal_class(),
            arkret_wire::SignalClass::Moderation
        );
        assert_eq!(moderation.signal_class().max_ttl().num_seconds(), 60);

        let candidate = SignalPayload::CallSignal {
            call_id,
            signal_kind: "candidate".to_owned(),
            data: Some(json!({"sdp_mid": "0"})),
        };
        assert_eq!(candidate.signal_class(), arkret_wire::SignalClass::Session);
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
                group_state_ref: "ak:event:01964200-0000-7000-8000-000000000004".to_owned(),
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
                alg: "EdDSA".to_owned(),
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
                .to_plaintext(
                    &actor(),
                    &realm(),
                    SignalSequence(0),
                    crate::clock::now_utc()
                )
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
}
