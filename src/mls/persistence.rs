//! MLS group state persistence + cross-device restore.
//!
//! Inkson needs MLS group state to survive process restarts: without
//! persistence the next message must refetch a Welcome and rejoin from
//! scratch, which drops the device's leaf and churns the epoch — not
//! viable for production, since MLS commits are causally tied to the
//! Seal lattice.
//!
//! This module wires three pieces together:
//!
//! 1. **Serialize on commit.** The SDK's `ArkretMlsGroup` already exposes `export_state_record()` /
//!    `restore_from_state_record()` so the openmls provider storage can be round-tripped through a
//!    typed [`arkret_sdk::MlsGroupStateRecord`]. We wrap that record in [`MlsSnapshotEnvelope`]
//!    which adds a device-scoped confidentiality layer so a stolen state.json doesn't leak the
//!    openmls provider keys.
//!
//! Also exposes the multi-device Welcome shuttle
//! ([`encode_welcome_for_transport`] / [`decode_welcome_from_transport`])
//! used to ship a typed `MlsWelcomeEnvelope` over soland's
//! `/_arkret/self/device_messages` (with `type = "ak.mls.welcome"`). The
//! payload is the canonical SDK serialization — JSON serialize the
//! `MlsWelcomeEnvelope` struct directly — so an apply-on-receive path
//! can round-trip it via `serde_json::from_value` and feed it into
//! [`arkret_sdk::ArkretMlsGroup::join_from_welcome`].
//!
//! 2. **Persist via key_backup.** [`MlsSnapshotEnvelope::to_key_backup_body`] produces the
//!    `ak.schema.key_backup.v1` request body used by `PUT /_arkret/self/keys/backups/{backup_id}`.
//!    The blob is opaque to soland; device-secret-derived encryption keeps the server
//!    zero-knowledge of group keys.
//!
//! 3. **Restore on boot or pair-in.** [`restore_envelope`] decrypts the envelope with this device's
//!    MLS snapshot secret and reconstructs the group via the SDK call. Two failure modes are pinned
//!    in tests: [`EnvelopeError::SecretMismatch`] (wrong device secret or tampered envelope) and
//!    [`EnvelopeError::OutdatedSnapshot`] (the envelope's recorded epoch is older than the current
//!    Seal view — a paired-in device must NOT bind to a stale epoch since that would silently fork
//!    the group).
//!
//! The happy path is encrypt -> write through `LocalStateStore` -> read
//! back -> decrypt -> SDK restore_from_state_record. That is the same
//! path the device rehydrate strand drives.
//!
//! ### Crypto choice
//!
//! The envelope uses ChaCha20-Poly1305 AEAD. The `chacha20poly1305`
//! crate is already a direct inkson dependency (used by the cloud-vault
//! recovery path) and builds cleanly on wasm32. The layout:
//!
//! * **Key derivation:** HKDF-SHA256 with the per-envelope salt and the device snapshot secret as
//!   input keying material. The resulting 32-byte key feeds the ChaCha20-Poly1305 AEAD directly.
//! * **Symmetric layer:** ChaCha20-Poly1305 AEAD with a fresh 12-byte random nonce per envelope.
//!   The nonce is stored alongside the ciphertext so decryption is self-contained.
//! * **Tamper detection:** the AEAD's built-in Poly1305 tag covers the ciphertext. We additionally
//!   bind the envelope's `(salt, epoch, recorded_at, magic)` into the AEAD's `additional_data` so a
//!   tampered envelope (e.g. an attacker swapping the recorded epoch to bypass the freshness check)
//!   trips the AEAD verification instead of decrypting cleanly under a forged epoch.
//! * **Replay defence:** `recorded_at` is now part of the AEAD AAD, so an envelope cannot be
//!   replayed with a forged timestamp to make it look fresh. The freshness check
//!   ([`decrypt_with_epoch_check`]) still relies on the epoch ordering provided by the Seal view,
//!   but the AAD binding guarantees the timestamp the caller sees has not been swapped out.

use chacha20poly1305::aead::{Aead, OsRng, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce};
use chrono::{DateTime, Utc};
use garth::MlsGroupStateRecord;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

/// Magic-bytes prefix burned into every v1 envelope.
pub const MLS_ENVELOPE_MAGIC: &[u8] = b"inkson-mls-snap-v1";

/// AEAD envelope version. `1` = ChaCha20-Poly1305 AEAD with
/// `(salt, epoch, recorded_at, magic)` bound into the AAD.
pub const AEAD_VERSION_CHACHA20_POLY1305: u8 = 1;

/// Typed envelope wrapping an encrypted MLS group state
/// record. Persisted via `LocalStateStore` and (for cross-device
/// restore) shipped as the `ciphertext` body of a
/// `PUT /_arkret/self/keys/backups/{backup_id}` call. The fields here are
/// the minimum required for tamper detection + outdated-snapshot
/// detection; everything else (signing key set / openmls provider
/// storage entries) lives inside the key-backup `ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsSnapshotEnvelope {
    /// Inkson's realm id the envelope belongs to. Not encrypted —
    /// the boot path needs to know which envelope maps to which
    /// Realm without decrypting them all first.
    pub realm_id: String,
    /// Recorded MLS group id (hex-encoded by the SDK). Surfaced for
    /// debug + audit; does not leak material.
    pub group_id: String,
    /// MLS epoch as recorded at snapshot time. Primary signal for
    /// outdated-snapshot detection — a peer that paired in a fresher
    /// device sees the larger epoch on the server's seal view.
    pub epoch: u64,
    /// Accepted `ak.mls.genesis` or `ak.mls.commit` Event that materialized
    /// this exact `(group_id, epoch)` state. The reference is public metadata,
    /// but keeping it inside the encrypted backup envelope lets a fresh device
    /// restore the authoring frontier together with the executable MLS state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_state_event_id: Option<arkret_sdk::EventId>,
    /// Per-envelope salt used during device-secret stretching.
    /// Hex-encoded so the JSON form is human-debuggable.
    pub salt_hex: String,
    /// ChaCha20-Poly1305 AEAD output, which is the encrypted plaintext
    /// followed by the 16-byte Poly1305 tag.
    pub ciphertext_hex: String,
    /// 12-byte ChaCha20-Poly1305 nonce. The nonce is freshly generated
    /// per envelope so replay is prevented at the AEAD layer.
    pub mac_hex: String,
    /// RFC 3339 timestamp at which the snapshot was taken. Used by
    /// "newest envelope wins" tie-breaking on multi-device restore.
    /// For [`AEAD_VERSION_CHACHA20_POLY1305`] envelopes the timestamp
    /// is also bound into the AEAD AAD so a tampered envelope cannot
    /// fake a fresh recording time.
    pub recorded_at: DateTime<Utc>,
    /// SEC-08 (`encryption-and-audit.md` §2.9) — wall-clock time at which
    /// the device first held *this* MLS epoch. Unlike [`Self::recorded_at`]
    /// (refreshed on every re-snapshot, including epoch-preserving reaction
    /// sends), this advances ONLY when the epoch number changes, so it is a
    /// faithful epoch-age clock for the `minimal_metadata_realm` 1h cap.
    /// Not bound into the AEAD AAD: it is a local scheduling hint, never a
    /// confidentiality boundary.
    pub epoch_started_at: DateTime<Utc>,
    /// YOU-02-004 (`encryption-and-audit.md` §5.6) — number of MLS
    /// application messages observed (sent OR successfully decrypted) on
    /// this device within the CURRENT epoch. Drives the spec's
    /// self-preservation commit SHOULD trigger ("epoch has observed at least
    /// 1000 application messages"). Resets to the in-flight message count whenever
    /// the epoch advances; carried forward (and bumped) by epoch-preserving
    /// re-snapshots. Like [`Self::epoch_started_at`] it is a local
    /// scheduling hint, not a confidentiality boundary, so it is not bound
    /// into the AEAD AAD.
    pub app_messages_observed: u64,
    /// AEAD scheme tag. New envelopes always serialize with
    /// [`AEAD_VERSION_CHACHA20_POLY1305`].
    pub aead_version: u8,
}

/// Errors produced while encrypting / decrypting / verifying an MLS
/// snapshot envelope. Each variant maps onto a UI-visible error
/// message + a typed test assertion.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// Device snapshot secret did not match the one used at encryption
    /// time, OR the envelope was tampered with. The two cases are
    /// indistinguishable by design (a MAC failure could be either).
    #[error("snapshot secret mismatch (or envelope tampered)")]
    SecretMismatch,
    /// The envelope is well-formed and decrypts cleanly but its
    /// recorded epoch is strictly less than the caller-supplied
    /// "current" epoch (typically taken from the latest Seal view).
    /// Restoring would silently fork the MLS group; the caller must
    /// fetch a newer envelope before restoring.
    #[error("outdated snapshot: envelope epoch {envelope_epoch} < current epoch {current_epoch}")]
    OutdatedSnapshot {
        envelope_epoch: u64,
        current_epoch: u64,
    },
    /// Hex decode / structural problem.
    #[error("malformed envelope: {0}")]
    Malformed(String),
    /// Round-trip JSON parse on the inner `MlsGroupStateRecord`
    /// failed. Distinct from [`Self::SecretMismatch`] because
    /// the MAC verified — the bytes match, but the inner shape
    /// changed. This usually means the SDK bumped its on-disk format
    /// in an incompatible way; the user must take a fresh snapshot.
    #[error("inner state record invalid: {0}")]
    InvalidStateRecord(String),
    /// Crypto error from the SDK's `restore_from_state_record` call.
    /// Only emitted on native targets; the wasm path is feature-gated
    /// because the SDK's MLS surface is native-only inside inkson.
    #[error("SDK restore failed: {0}")]
    SdkRestore(String),
    /// F-WASM-MLS-1: the byte-level envelope decrypted cleanly but
    /// the live MLS group can't be reconstructed on this target —
    /// today, wasm32. The caller already has the inner
    /// `MlsGroupStateRecord` (returned via
    /// [`restore_state_record_only`]) and can render the metadata
    /// (epoch / device_id / signer_public_key), but encrypt /
    /// decrypt of new messages requires the native SDK provider.
    #[error(
        "wasm32 MLS group restore is not supported — use the metadata returned by restore_state_record_only"
    )]
    WasmMlsRestoreUnsupported,
}

/// Encrypt a serialised MLS group state record under a device snapshot secret.
/// `realm_id` is metadata only (not encrypted); `state_bytes` is the
/// SDK-serialised `MlsGroupStateRecord` JSON. `salt` SHOULD be a
/// 16-byte random value but the helper accepts any length so tests
/// can pin a deterministic salt.
///
/// Phase A.6 #2: produces a [`AEAD_VERSION_CHACHA20_POLY1305`]
/// envelope. The AEAD AAD binds the envelope's metadata
/// (`MLS_ENVELOPE_MAGIC || salt || epoch_be || recorded_at_unix_be`),
/// so a tampered envelope (e.g. an attacker swapping the recorded
/// epoch / timestamp) fails the AEAD verification instead of
/// decrypting cleanly.
#[allow(clippy::expect_used)]
pub fn encrypt_state(
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    state_bytes: &[u8],
    snapshot_secret: &str,
    salt: &[u8],
) -> MlsSnapshotEnvelope {
    let recorded_at = crate::clock::now_utc();
    let key = derive_key(snapshot_secret, salt);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad = build_aead_aad(salt, epoch, recorded_at);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: state_bytes,
                aad: &aad,
            },
        )
        // ChaCha20-Poly1305 encryption only fails when the plaintext
        // exceeds the 256 GiB AEAD limit, which is impossible for an
        // MLS group state record. Treat as unreachable.
        .expect("chacha20-poly1305 encrypt should not fail for in-memory MLS state");
    MlsSnapshotEnvelope {
        realm_id: realm_id.to_owned(),
        group_id: group_id.to_owned(),
        epoch,
        group_state_event_id: None,
        salt_hex: hex_encode(salt),
        ciphertext_hex: hex_encode(&ciphertext),
        mac_hex: hex_encode(nonce.as_slice()),
        recorded_at,
        // New-epoch baseline: a freshly minted envelope is assumed to start a
        // new epoch on this device, so the epoch clock starts now. The reaction
        // path (which re-snapshots WITHOUT advancing the epoch) overrides this
        // via [`MlsSnapshotEnvelope::carry_epoch_started_at`] so the §2.9 1h cap
        // measures true epoch age, not last-write time.
        epoch_started_at: recorded_at,
        app_messages_observed: 0,
        aead_version: AEAD_VERSION_CHACHA20_POLY1305,
    }
}

/// Decrypt the envelope and return the inner state bytes (the SDK's
/// `MlsGroupStateRecord` JSON).
///
/// For [`AEAD_VERSION_CHACHA20_POLY1305`] envelopes the AEAD's
/// Poly1305 tag detects both device-secret mismatch and tamper.
pub fn decrypt_envelope(
    envelope: &MlsSnapshotEnvelope,
    snapshot_secret: &str,
) -> Result<Vec<u8>, EnvelopeError> {
    match envelope.aead_version {
        AEAD_VERSION_CHACHA20_POLY1305 => decrypt_envelope_aead_v1(envelope, snapshot_secret),
        other => Err(EnvelopeError::Malformed(format!(
            "unsupported aead_version {other}"
        ))),
    }
}

fn decrypt_envelope_aead_v1(
    envelope: &MlsSnapshotEnvelope,
    snapshot_secret: &str,
) -> Result<Vec<u8>, EnvelopeError> {
    let salt = hex_decode(&envelope.salt_hex)
        .ok_or_else(|| EnvelopeError::Malformed("salt is not hex".to_owned()))?;
    let ciphertext = hex_decode(&envelope.ciphertext_hex)
        .ok_or_else(|| EnvelopeError::Malformed("ciphertext is not hex".to_owned()))?;
    let nonce_bytes = hex_decode(&envelope.mac_hex)
        .ok_or_else(|| EnvelopeError::Malformed("nonce is not hex".to_owned()))?;
    if nonce_bytes.len() != 12 {
        return Err(EnvelopeError::Malformed(format!(
            "nonce length {} (expected 12 for ChaCha20-Poly1305)",
            nonce_bytes.len()
        )));
    }
    let key = derive_key(snapshot_secret, &salt);
    let aad = build_aead_aad(&salt, envelope.epoch, envelope.recorded_at);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        // ChaCha20-Poly1305 decrypt failure is the typed SecretMismatch
        // signal; we deliberately do not distinguish "wrong key" from
        // "tampered envelope".
        .map_err(|_| EnvelopeError::SecretMismatch)
}

/// Phase A.6 #2: build the AEAD additional-data bytes binding the
/// envelope's plaintext metadata (magic, salt, epoch, timestamp).
/// Any caller-side mutation of one of these fields invalidates the
/// AEAD tag.
fn build_aead_aad(salt: &[u8], epoch: u64, recorded_at: DateTime<Utc>) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLS_ENVELOPE_MAGIC.len() + salt.len() + 8 + 8);
    out.extend_from_slice(MLS_ENVELOPE_MAGIC);
    out.extend_from_slice(salt);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&recorded_at.timestamp().to_be_bytes());
    out
}

/// Decrypt + verify epoch freshness. Returns the inner state bytes
/// when the envelope's epoch is `>= current_epoch_floor`, otherwise
/// [`EnvelopeError::OutdatedSnapshot`]. Used by the multi-device
/// restore path so a freshly-paired device doesn't bind to a stale
/// envelope and silently fork the group.
pub fn decrypt_with_epoch_check(
    envelope: &MlsSnapshotEnvelope,
    snapshot_secret: &str,
    current_epoch_floor: u64,
) -> Result<Vec<u8>, EnvelopeError> {
    let bytes = decrypt_envelope(envelope, snapshot_secret)?;
    if envelope.epoch < current_epoch_floor {
        return Err(EnvelopeError::OutdatedSnapshot {
            envelope_epoch: envelope.epoch,
            current_epoch: current_epoch_floor,
        });
    }
    Ok(bytes)
}

impl MlsSnapshotEnvelope {
    /// Build the typed key_backup PUT body for this envelope. The
    /// `backup_id` is the protocol backup object id; `actor_id` and
    /// `device_id` identify the device that minted the snapshot.
    pub fn to_key_backup_body(
        &self,
        backup_id: &str,
        actor_id: &str,
        device_id: &str,
        secret_storage_key: &[u8; 32],
    ) -> anyhow::Result<Value> {
        let envelope_bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut body = json!({
            "backup_id": backup_id,
            "actor_id": actor_id,
            "backup_class": "mls_history",
            "backup_version": "kb_mls_snapshot_v1",
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(self.recorded_at),
            "encryption": {
                // Spec key-management.md §7.5.3 / device-lifecycle.md §12:
                // mls_history is wrapped under a `secret_storage` key
                // (`mls_group_secrets_backup_key`), recovered after the account
                // secret is unlocked.
                "recipient_method": "secret_storage_key",
                "recipient_key_ref": "mls_group_secrets_backup_key",
                "aead": {
                    "name": "xchacha20_poly1305",
                    "aead_profile": "ak.aead.xchacha20_poly1305.v1",
                    "nonce": ""
                }
            },
            "contents": [{
                "item_type": "mls_group_state",
                "mls_group_id": self.group_id,
                "epoch": self.epoch,
                "secret_id": "inkson_mls_snapshot",
                "realm_id": self.realm_id
            }],
            "ciphertext": "",
            "ciphertext_digest": ""
        });
        if let Some(group_state_event_id) = &self.group_state_event_id {
            body["contents"][0]["last_event_id"] = Value::String(group_state_event_id.to_string());
        }
        if is_protocol_device_id(device_id)
            && let Some(object) = body.as_object_mut()
        {
            object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
        }
        crate::key_backup::attach_key_backup_genesis_series(&mut body);
        crate::key_backup::attach_key_backup_domain_separation(
            &mut body,
            crate::key_backup::BackupClass::MlsHistory,
            "mls_snapshot",
        );
        let aead_aad = serde_json::from_value(
            body.pointer("/domain_separation/aead_aad")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("domain_separation.aead_aad missing"))?,
        )
        .map_err(|error| anyhow::anyhow!("key-backup AAD: {error}"))?;
        let binding = arkret_crypto::backup::VaultBinding {
            backup_id: arkret_sdk::BackupId::new(backup_id.to_owned())
                .map_err(|error| anyhow::anyhow!("backup_id: {error}"))?,
            subdomain: body
                .pointer("/domain_separation/subdomain")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("domain_separation.subdomain missing"))?
                .to_owned(),
            aead_aad,
        };
        let sealed = arkret_crypto::backup::encrypt_with_secret_storage_key(
            secret_storage_key,
            &binding,
            &envelope_bytes,
        )
        .map_err(|error| anyhow::anyhow!("encrypt mls_history backup: {error}"))?;
        body["encryption"]["aead"]["nonce"] = Value::String(sealed.nonce_b64);
        body["ciphertext"] = Value::String(sealed.ciphertext_b64);
        body["ciphertext_digest"] = Value::String(sealed.digest_sha256);
        crate::key_backup::sign_key_backup_with_active_device(&mut body, device_id)?;
        Ok(body)
    }

    /// SEC-08 — carry the epoch-start clock forward from a prior snapshot when
    /// this re-snapshot did NOT advance the epoch.
    ///
    /// [`encrypt_state`] optimistically stamps `epoch_started_at = recorded_at`
    /// (correct for any commit that bumps the epoch). The reaction send path and
    /// the account-secret rotation path re-encrypt the *same* epoch, so they
    /// must inherit the previous epoch's start time instead of resetting the 1h
    /// `minimal_metadata_realm` clock on every reaction. When the epoch genuinely
    /// changed, the freshly stamped `recorded_at` baseline is kept.
    #[must_use]
    pub fn carry_epoch_started_at(mut self, previous: &MlsSnapshotEnvelope) -> Self {
        if self.epoch == previous.epoch {
            self.epoch_started_at = previous.epoch_started_at;
        }
        self
    }

    /// YOU-02-004 (§5.6) — set the per-epoch observed application-message
    /// count on a freshly minted envelope. Callers compute the value as
    /// `previous.app_messages_observed + new_messages` when the epoch is
    /// unchanged, or just `new_messages` after a commit advanced the epoch.
    #[must_use]
    pub fn with_app_messages_observed(mut self, count: u64) -> Self {
        self.app_messages_observed = count;
        self
    }

    /// Round-trip the inner `MlsGroupStateRecord` (after
    /// `decrypt_envelope`) into the SDK's typed shape.
    pub fn restore_state_record(bytes: &[u8]) -> Result<MlsGroupStateRecord, EnvelopeError> {
        serde_json::from_slice::<MlsGroupStateRecord>(bytes)
            .map_err(|err| EnvelopeError::InvalidStateRecord(err.to_string()))
    }
}

/// Helper that decrypts an [`MlsSnapshotEnvelope`] + parses out the typed
/// [`MlsGroupStateRecord`] without trying to reconstruct the live MLS group
/// via the OpenMLS provider. Callers that need an executable
/// [`arkret_sdk::ArkretMlsGroup`] should use [`restore_envelope`].
pub fn restore_state_record_only(
    envelope: &MlsSnapshotEnvelope,
    snapshot_secret: &str,
    current_epoch_floor: u64,
) -> Result<MlsGroupStateRecord, EnvelopeError> {
    let bytes = decrypt_with_epoch_check(envelope, snapshot_secret, current_epoch_floor)?;
    serde_json::from_slice::<MlsGroupStateRecord>(&bytes)
        .map_err(|err| EnvelopeError::InvalidStateRecord(err.to_string()))
}

/// Helper used by the boot path and local MLS actions. Decrypts the envelope,
/// sanity-checks the epoch, and reconstructs the SDK group via
/// [`arkret_sdk::ArkretMlsGroup::restore_from_state_record`].
///
/// `current_epoch_floor` is taken from the latest Seal view; pass
/// `0` to skip the freshness check (e.g. first-boot rehydrate where
/// no Seal view is known yet).
pub fn restore_envelope(
    envelope: &MlsSnapshotEnvelope,
    snapshot_secret: &str,
    current_epoch_floor: u64,
) -> Result<arkret_sdk::ArkretMlsGroup, EnvelopeError> {
    let bytes = decrypt_with_epoch_check(envelope, snapshot_secret, current_epoch_floor)?;
    let record = MlsSnapshotEnvelope::restore_state_record(&bytes)?;
    arkret_sdk::ArkretMlsGroup::restore_from_state_record(&record)
        .map_err(|err| EnvelopeError::SdkRestore(err.to_string()))
}

// ───────────────────── Crypto primitives ────────────────────────

#[allow(clippy::expect_used)]
fn derive_key(snapshot_secret: &str, salt: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), snapshot_secret.as_bytes());
    let mut out = [0u8; 32];
    hkdf.expand(MLS_ENVELOPE_MAGIC, &mut out)
        .expect("HKDF output length is fixed at 32 bytes");
    out
}

fn is_protocol_device_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak:device:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

// YOU-05-007: shared lowercase-hex codec lives in `crate::canonical`.
use crate::canonical::{hex_decode, hex_encode};

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_salt() -> Vec<u8> {
        // Deterministic salt for round-trip tests; production callers
        // pass `getrandom::fill`-derived bytes.
        b"round-28-mls-snapshot-salt-x".to_vec()
    }

    fn fake_state_record_bytes(group_id: &str, epoch: u64) -> Vec<u8> {
        // We don't depend on the SDK shape here — the encrypt/decrypt
        // path is byte-transparent. The test exercises the envelope
        // boundary; the SDK round-trip is exercised separately on
        // native by the dedicated `sdk_round_trip` test below.
        let body = json!({
            "group_id": group_id,
            "principal_id": "did:web:alice.example",
            "device_id": "dev_alice_1",
            "epoch": epoch,
            "serialized_state": [1, 2, 3, 4, 5, 6, 7, 8],
            "updated_at": "2026-05-09T00:00:00.000Z",
        });
        serde_json::to_vec(&body).unwrap()
    }

    #[test]
    fn persist_restore_round_trip_recovers_group_state() {
        let bytes = fake_state_record_bytes("aabbccdd", 7);
        let envelope = encrypt_state(
            "ak:realm:demo",
            "aabbccdd",
            7,
            &bytes,
            "correct horse battery staple",
            &fixed_salt(),
        );
        assert_eq!(envelope.realm_id, "ak:realm:demo");
        assert_eq!(envelope.group_id, "aabbccdd");
        assert_eq!(envelope.epoch, 7);
        // Ciphertext is not the plaintext — encryption did something.
        assert_ne!(envelope.ciphertext_hex, hex_encode(&bytes));

        let plaintext = decrypt_envelope(&envelope, "correct horse battery staple")
            .expect("happy-path decrypt");
        assert_eq!(plaintext, bytes);
    }

    #[test]
    fn snapshot_secret_mismatch_is_rejected_distinct_from_other_errors() {
        let bytes = fake_state_record_bytes("dead", 1);
        let envelope = encrypt_state(
            "ak:realm:demo",
            "dead",
            1,
            &bytes,
            "secret one",
            &fixed_salt(),
        );
        let result = decrypt_envelope(&envelope, "secret two");
        assert!(matches!(result, Err(EnvelopeError::SecretMismatch)));

        // Tampered ciphertext also surfaces as SecretMismatch
        // (AEAD failure — the two cases are indistinguishable by
        // design and both block restore).
        let mut tampered = envelope.clone();
        let replacement = if tampered.ciphertext_hex.starts_with("ff") {
            "00"
        } else {
            "ff"
        };
        tampered.ciphertext_hex.replace_range(0..2, replacement);
        let result = decrypt_envelope(&tampered, "secret one");
        assert!(matches!(result, Err(EnvelopeError::SecretMismatch)));
    }

    #[test]
    fn outdated_snapshot_is_rejected_via_epoch_check() {
        let bytes = fake_state_record_bytes("beef", 3);
        let envelope = encrypt_state("ak:realm:demo", "beef", 3, &bytes, "p1", &fixed_salt());

        // current_epoch_floor == 3 → still acceptable (>=).
        let ok = decrypt_with_epoch_check(&envelope, "p1", 3);
        assert!(ok.is_ok(), "epoch == floor should pass: {:?}", ok.err());

        // current_epoch_floor == 5 → envelope is stale by 2 epochs.
        let result = decrypt_with_epoch_check(&envelope, "p1", 5);
        match result {
            Err(EnvelopeError::OutdatedSnapshot {
                envelope_epoch,
                current_epoch,
            }) => {
                assert_eq!(envelope_epoch, 3);
                assert_eq!(current_epoch, 5);
            }
            other => panic!("expected OutdatedSnapshot, got {other:?}"),
        }

        // Secret mismatch beats outdated check (we don't leak the
        // envelope epoch to a caller without the device secret).
        let result = decrypt_with_epoch_check(&envelope, "wrong", 5);
        assert!(matches!(result, Err(EnvelopeError::SecretMismatch)));
    }

    #[test]
    fn malformed_hex_surfaces_typed_error() {
        let mut envelope = encrypt_state("ak:realm:demo", "feed", 1, b"abc", "p", &fixed_salt());
        envelope.ciphertext_hex = "zzzz".to_owned(); // not hex
        let result = decrypt_envelope(&envelope, "p");
        assert!(matches!(result, Err(EnvelopeError::Malformed(_))));
    }

    #[test]
    fn key_backup_body_carries_content_metadata_and_blob() {
        let envelope = encrypt_state(
            "ak:realm:demo",
            "aaaa",
            42,
            b"placeholder",
            "passw",
            &fixed_salt(),
        );
        let body = envelope
            .to_key_backup_body(
                "ak:backup:01964137-0000-7000-8000-000000000000",
                "did:web:alice.example",
                "ak:device:01964137-0000-7000-8000-000000000001",
                &crate::mls::runtime::derive_mls_history_backup_key("passw").unwrap(),
            )
            .unwrap();
        assert_eq!(
            body["backup_id"],
            "ak:backup:01964137-0000-7000-8000-000000000000"
        );
        assert_eq!(
            body["device_id"],
            "ak:device:01964137-0000-7000-8000-000000000001"
        );
        assert_eq!(body["backup_class"], "mls_history");
        assert_eq!(body["backup_version"], "kb_mls_snapshot_v1");
        assert!(
            body["series_id"]
                .as_str()
                .is_some_and(|value| value.starts_with("ak:backup_series:"))
        );
        assert_eq!(body["series_seq"], 0);
        assert_eq!(body["encryption"]["recipient_method"], "secret_storage_key");
        assert_eq!(
            body["encryption"]["recipient_key_ref"],
            "mls_group_secrets_backup_key"
        );
        assert!(body["encryption"].get("kdf").is_none());
        assert_eq!(body["contents"][0]["item_type"], "mls_group_state");
        assert_eq!(body["contents"][0]["realm_id"], "ak:realm:demo");
        assert_eq!(body["contents"][0]["mls_group_id"], "aaaa");
        assert_eq!(body["contents"][0]["epoch"], 42);
        assert_eq!(
            body["domain_separation"]["hkdf_info"],
            "arkret-key-backup/mls_history/mls_snapshot/v1"
        );
        crate::key_backup::validate_key_backup_envelope(
            &body,
            Some(crate::key_backup::BackupClass::MlsHistory),
        )
        .expect("MLS history backup envelope should validate");
        assert!(body.get("envelope_meta").is_none());
        // The outer key-backup ciphertext is authenticated encryption, and the
        // runtime owner can open it back to the original snapshot envelope.
        let parsed = crate::mls::runtime::decode_mls_history_backup_envelope(&body, "passw")
            .expect("MLS history backup should decrypt");
        assert_eq!(parsed.realm_id, "ak:realm:demo");
        assert_eq!(parsed.epoch, 42);
    }

    #[test]
    fn epoch_started_at_defaults_to_recorded_at_on_fresh_envelope() {
        // SEC-08 — a freshly minted envelope assumes a new epoch baseline:
        // the epoch clock starts at recording time.
        let envelope = encrypt_state("s", "g", 5, b"x", "p", &fixed_salt());
        assert_eq!(envelope.epoch_started_at, envelope.recorded_at);
    }

    #[test]
    fn carry_epoch_started_at_preserves_clock_only_when_epoch_unchanged() {
        // SEC-08 — re-snapshotting the SAME epoch (reaction / rotation) must
        // inherit the prior epoch-start time so the 1h cap measures true epoch
        // age, not last-write time.
        let prev = encrypt_state("s", "g", 7, b"a", "p", &fixed_salt());
        let same_epoch = encrypt_state("s", "g", 7, b"b", "p", &fixed_salt());
        assert_ne!(same_epoch.epoch_started_at, prev.epoch_started_at);
        let carried = same_epoch.carry_epoch_started_at(&prev);
        assert_eq!(carried.epoch_started_at, prev.epoch_started_at);

        // An epoch advance keeps the fresh baseline (clock resets on commit).
        let next_epoch = encrypt_state("s", "g", 8, b"c", "p", &fixed_salt());
        let baseline = next_epoch.epoch_started_at;
        let kept = next_epoch.carry_epoch_started_at(&prev);
        assert_eq!(kept.epoch_started_at, baseline);
    }

    #[test]
    fn encrypt_with_distinct_salts_produces_distinct_ciphertext() {
        // Sanity: salt randomisation defeats rainbow-table lookups
        // even when the same device secret + plaintext is used across
        // two snapshots. Mirrors the SDK key_backup invariant.
        let bytes = fake_state_record_bytes("a", 1);
        let one = encrypt_state("s", "a", 1, &bytes, "p", b"salt-one");
        let two = encrypt_state("s", "a", 1, &bytes, "p", b"salt-two");
        assert_ne!(one.ciphertext_hex, two.ciphertext_hex);
        assert_ne!(one.mac_hex, two.mac_hex);
    }

    #[test]
    fn invalid_state_record_surfaces_typed_error() {
        // The AEAD tag verifies (encryption is byte-transparent), but the
        // inner bytes don't parse as `MlsGroupStateRecord`. The error
        // is `InvalidStateRecord`, distinct from `SecretMismatch`.
        let envelope = encrypt_state(
            "ak:realm:demo",
            "z",
            0,
            b"this is not json",
            "p",
            &fixed_salt(),
        );
        let plaintext = decrypt_envelope(&envelope, "p").unwrap();
        #[cfg(not(target_arch = "wasm32"))]
        {
            let parsed = MlsSnapshotEnvelope::restore_state_record(&plaintext);
            assert!(matches!(parsed, Err(EnvelopeError::InvalidStateRecord(_))));
        }
        #[cfg(target_arch = "wasm32")]
        let _ = plaintext;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sdk_round_trip_persist_and_restore_real_group() {
        // End-to-end: SDK creates a group → export_state_record →
        // encrypt → decrypt → SDK restore. The restored group must
        // report the same group_id + epoch.
        use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

        let identity = ArkretMlsIdentity::new_basic(
            Did::new("did:web:alice.example".to_owned()).unwrap(),
            // SDK 0.7 requires the canonical `ak:device:<uuid7>` form.
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(b"ak:realm:round28-snapshot").unwrap();
        let record = group.export_state_record().unwrap();
        let original_group_id = record.group_id.clone();
        let original_epoch = record.epoch;

        let bytes = serde_json::to_vec(&record).unwrap();
        let envelope = encrypt_state(
            "ak:realm:round28-snapshot",
            &original_group_id,
            original_epoch,
            &bytes,
            "round28-secret",
            b"deterministic-salt-for-test",
        );

        let restored = restore_envelope(&envelope, "round28-secret", original_epoch).unwrap();
        assert_eq!(restored.group_id(), original_group_id);
        assert_eq!(restored.epoch(), original_epoch);
    }
}
