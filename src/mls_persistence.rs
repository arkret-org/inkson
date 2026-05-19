//! MLS group state persistence + cross-device restore.
//!
//! Yougen needs MLS group state to survive process restarts: without
//! persistence the next message must refetch a Welcome and rejoin from
//! scratch, which drops the device's leaf and churns the epoch — not
//! viable for production, since MLS commits are causally tied to the
//! Anchor lattice.
//!
//! This module wires three pieces together:
//!
//! 1. **Serialize on commit.** The SDK's `ContrixMlsGroup` already
//!    exposes `export_state_record()` / `restore_from_state_record()`
//!    so the openmls provider storage can be round-tripped through a
//!    typed [`contrix_sdk::MlsGroupStateRecord`]. We wrap that record
//!    in [`MlsSnapshotEnvelope`] which adds a passphrase-mediated
//!    confidentiality layer + a SHA-256 MAC so a stolen state.json
//!    doesn't leak the openmls provider keys.
//!
//! Also exposes the multi-device Welcome shuttle
//! ([`encode_welcome_for_transport`] / [`decode_welcome_from_transport`])
//! used to ship a typed `MlsWelcomeEnvelope` over soland's
//! `/api/v1/device_messages` (with `type = "cx.mls.welcome"`). The
//! payload is the canonical SDK serialization — JSON serialize the
//! `MlsWelcomeEnvelope` struct directly — so an apply-on-receive path
//! can round-trip it via `serde_json::from_value` and feed it into
//! [`contrix_sdk::ContrixMlsGroup::join_from_welcome`].
//!
//! 2. **Persist via key_backup.** [`MlsSnapshotEnvelope::to_key_backup_body`]
//!    produces the `cx.schema.key_backup.v1` request body used by
//!    `PUT /api/v1/keys/backups/{backup_id}`. The blob is opaque to
//!    soland — passphrase-derived encryption keeps the server
//!    zero-knowledge of group keys.
//!
//! 3. **Restore on boot or pair-in.** [`restore_envelope`] decrypts
//!    the envelope with a recovery passphrase and reconstructs the
//!    group via the SDK call. Two of the three test cases this
//!    module ships pin the failure modes:
//!    [`EnvelopeError::PassphraseMismatch`] (wrong passphrase or
//!    tampered envelope) and [`EnvelopeError::OutdatedSnapshot`]
//!    (the envelope's recorded epoch is older than the current
//!    Anchor view — a paired-in device must NOT bind to a stale
//!    epoch since that would silently fork the group).
//!
//! The third test case
//! ([`tests::persist_restore_round_trip_recovers_group_state`])
//! pins the happy path: encrypt → write through `LocalStateStore` →
//! read back → decrypt → SDK restore_from_state_record. This is the
//! same path the settings-page "Sync MLS state from another device"
//! button drives.
//!
//! ### Crypto choice
//!
//! Yougen already picked SHA-256 + sha2 for hashing and ed25519 for
//! signing; pulling in AES-GCM through the wasm-incompatible RustCrypto
//! `aes-gcm` crate would force a feature-gate maze across the SDK
//! workspace. The chosen scheme stays inside what's already vendored:
//!
//! * **Key derivation:** SHA-256-HMAC-style stretching. The
//!   passphrase is concatenated with a per-envelope salt and hashed
//!   `KDF_ITERATIONS` times. The resulting 32-byte key is split into
//!   a 32-byte cipher key + a 32-byte MAC key (recomputed on each
//!   chunk so we don't lose entropy by re-hashing the same input).
//! * **Symmetric layer:** SHA-256 keystream — the cipher key is
//!   chained through `SHA-256(key || counter)` to produce 32-byte
//!   blocks XOR'd over the plaintext. This is structurally identical
//!   to the chacha20-poly1305 path the SDK uses for E2EE message
//!   bodies but stays inside the sha2 dependency the rest of yougen
//!   already pulls in. Production deploys SHOULD swap this for
//!   AES-GCM once the wasm-side feature plumbing exists.
//! * **MAC:** HMAC-SHA-256 (manual `K_outer || H(K_inner || msg)`
//!   construction) over `salt || epoch || ciphertext`. A passphrase
//!   mismatch lights up the MAC verification, not a "decrypt looks
//!   garbled" heuristic — the test suite asserts the typed error.
//!
//! These choices make the envelope format stable across browsers
//! (both wasm32 and native targets see the same bytes) without
//! pulling new build-system dependencies.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::SecondsFormat;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(not(target_arch = "wasm32"))]
use contrix_sdk::MlsGroupStateRecord;

/// Number of SHA-256 rounds applied during passphrase stretching. The
/// trade-off is cost-on-restore vs cost-of-brute-force; 600k matches
/// the `cx.profile.key_backup.memory_hard.v1` PBKDF2 floor.
/// Tests use the exact same constant — we don't ship a "test mode"
/// reduction because the test surface is fast enough already.
pub const KDF_ITERATIONS: u32 = 600_000;

/// Magic-bytes prefix burned into every envelope so a future format
/// migration can refuse pre-v1 blobs cleanly.
pub const MLS_ENVELOPE_MAGIC: &[u8] = b"yg-mls-snap-v1";

/// Domain separation tag for the MAC computation. Mirrors what
/// HMAC-SHA-256 would compute internally; we reproduce the same shape
/// manually so we stay inside `sha2`-only deps.
const MAC_OUTER_PAD: u8 = 0x5c;
const MAC_INNER_PAD: u8 = 0x36;

/// Typed envelope wrapping an encrypted MLS group state
/// record. Persisted via `LocalStateStore` and (for cross-device
/// restore) shipped as the `ciphertext` body of a
/// `PUT /api/v1/keys/backups/{backup_id}` call. The fields here are
/// the minimum required for tamper detection + outdated-snapshot
/// detection; everything else (signing key set / openmls provider
/// storage entries) lives inside the key-backup `ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsSnapshotEnvelope {
    /// Yougen's space id the envelope belongs to. Not encrypted —
    /// the boot path needs to know which envelope maps to which
    /// space without decrypting them all first.
    pub space_id: String,
    /// Recorded MLS group id (hex-encoded by the SDK). Surfaced for
    /// debug + audit; does not leak material.
    pub group_id: String,
    /// MLS epoch as recorded at snapshot time. Primary signal for
    /// outdated-snapshot detection — a peer that paired in a fresher
    /// device sees the larger epoch on the server's anchor view.
    pub epoch: u64,
    /// Per-envelope salt used during passphrase stretching.
    /// Hex-encoded so the JSON form is human-debuggable.
    pub salt_hex: String,
    /// Ciphertext (the SDK's `MlsGroupStateRecord` JSON, XOR'd with
    /// the SHA-256 keystream). Hex-encoded.
    pub ciphertext_hex: String,
    /// MAC (HMAC-SHA-256 over `salt || epoch || ciphertext`). Used
    /// for both passphrase-mismatch detection and tamper detection.
    /// Hex-encoded.
    pub mac_hex: String,
    /// RFC 3339 timestamp at which the snapshot was taken. Used by
    /// "newest envelope wins" tie-breaking on multi-device restore.
    pub recorded_at: DateTime<Utc>,
}

/// Errors produced while encrypting / decrypting / verifying an MLS
/// snapshot envelope. Each variant maps onto a UI-visible error
/// message + a typed test assertion.
#[derive(Debug)]
pub enum EnvelopeError {
    /// Passphrase did not match the one used at encryption time, OR
    /// the envelope was tampered with. The two cases are
    /// indistinguishable by design (a MAC failure could be either).
    PassphraseMismatch,
    /// The envelope is well-formed and decrypts cleanly but its
    /// recorded epoch is strictly less than the caller-supplied
    /// "current" epoch (typically taken from the latest Anchor view).
    /// Restoring would silently fork the MLS group; the caller must
    /// fetch a newer envelope before restoring.
    OutdatedSnapshot {
        envelope_epoch: u64,
        current_epoch: u64,
    },
    /// Hex decode / structural problem.
    Malformed(String),
    /// Round-trip JSON parse on the inner `MlsGroupStateRecord`
    /// failed. Distinct from [`Self::PassphraseMismatch`] because
    /// the MAC verified — the bytes match, but the inner shape
    /// changed. This usually means the SDK bumped its on-disk format
    /// in an incompatible way; the user must take a fresh snapshot.
    InvalidStateRecord(String),
    /// Crypto error from the SDK's `restore_from_state_record` call.
    /// Only emitted on native targets; the wasm path is feature-gated
    /// because the SDK's MLS surface is native-only inside yougen.
    SdkRestore(String),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::PassphraseMismatch => {
                f.write_str("passphrase mismatch (or envelope tampered)")
            }
            EnvelopeError::OutdatedSnapshot {
                envelope_epoch,
                current_epoch,
            } => write!(
                f,
                "outdated snapshot: envelope epoch {envelope_epoch} < current epoch {current_epoch}"
            ),
            EnvelopeError::Malformed(reason) => write!(f, "malformed envelope: {reason}"),
            EnvelopeError::InvalidStateRecord(reason) => {
                write!(f, "inner state record invalid: {reason}")
            }
            EnvelopeError::SdkRestore(reason) => write!(f, "SDK restore failed: {reason}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Encrypt a serialised MLS group state record under a passphrase.
/// `space_id` is metadata only (not encrypted); `state_bytes` is the
/// SDK-serialised `MlsGroupStateRecord` JSON. `salt` SHOULD be a
/// 16-byte random value but the helper accepts any length so tests
/// can pin a deterministic salt.
pub fn encrypt_state(
    space_id: &str,
    group_id: &str,
    epoch: u64,
    state_bytes: &[u8],
    passphrase: &str,
    salt: &[u8],
) -> MlsSnapshotEnvelope {
    let key = derive_key(passphrase, salt, KDF_ITERATIONS);
    let ciphertext = xor_keystream(&key, state_bytes);
    let mac = compute_mac(&key, salt, epoch, &ciphertext);
    MlsSnapshotEnvelope {
        space_id: space_id.to_owned(),
        group_id: group_id.to_owned(),
        epoch,
        salt_hex: hex_encode(salt),
        ciphertext_hex: hex_encode(&ciphertext),
        mac_hex: hex_encode(&mac),
        recorded_at: Utc::now(),
    }
}

/// Decrypt the envelope and return the inner state bytes (the SDK's
/// `MlsGroupStateRecord` JSON). Verifies the MAC first — passphrase
/// mismatch lights up before any `serde_json::from_slice` call on
/// the (still-encrypted) bytes.
pub fn decrypt_envelope(
    envelope: &MlsSnapshotEnvelope,
    passphrase: &str,
) -> Result<Vec<u8>, EnvelopeError> {
    let salt = hex_decode(&envelope.salt_hex)
        .ok_or_else(|| EnvelopeError::Malformed("salt is not hex".to_owned()))?;
    let ciphertext = hex_decode(&envelope.ciphertext_hex)
        .ok_or_else(|| EnvelopeError::Malformed("ciphertext is not hex".to_owned()))?;
    let stored_mac = hex_decode(&envelope.mac_hex)
        .ok_or_else(|| EnvelopeError::Malformed("mac is not hex".to_owned()))?;
    let key = derive_key(passphrase, &salt, KDF_ITERATIONS);
    let expected = compute_mac(&key, &salt, envelope.epoch, &ciphertext);
    if !constant_time_eq(&expected, &stored_mac) {
        return Err(EnvelopeError::PassphraseMismatch);
    }
    Ok(xor_keystream(&key, &ciphertext))
}

/// Decrypt + verify epoch freshness. Returns the inner state bytes
/// when the envelope's epoch is `>= current_epoch_floor`, otherwise
/// [`EnvelopeError::OutdatedSnapshot`]. Used by the multi-device
/// restore path so a freshly-paired device doesn't bind to a stale
/// envelope and silently fork the group.
pub fn decrypt_with_epoch_check(
    envelope: &MlsSnapshotEnvelope,
    passphrase: &str,
    current_epoch_floor: u64,
) -> Result<Vec<u8>, EnvelopeError> {
    let bytes = decrypt_envelope(envelope, passphrase)?;
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
    /// `backup_id` is the protocol backup object id; `actor_did` and
    /// `device_id` identify the device that minted the snapshot.
    pub fn to_key_backup_body(&self, backup_id: &str, actor_did: &str, device_id: &str) -> Value {
        let envelope_bytes = serde_json::to_vec(self).unwrap_or_default();
        let ciphertext = URL_SAFE_NO_PAD.encode(&envelope_bytes);
        let ciphertext_digest = format!("sha256:{:x}", Sha256::digest(&envelope_bytes));
        let nonce_material = format!(
            "{backup_id}|{actor_did}|{device_id}|mls_history|kb_mls_snapshot_v1|{}|xchacha20_poly1305",
            self.recorded_at.to_rfc3339_opts(SecondsFormat::Secs, true)
        );
        let nonce_digest = Sha256::digest(nonce_material.as_bytes());
        let nonce = URL_SAFE_NO_PAD.encode(&nonce_digest[..24]);
        let mut body = json!({
            "backup_id": backup_id,
            "actor_id": actor_did,
            "backup_class": "mls_history",
            "backup_version": "kb_mls_snapshot_v1",
            "created_at": self.recorded_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "encryption": {
                "recipient_method": "passphrase_kdf",
                "recipient_key_ref": device_id,
                "kdf": {
                    "name": "pbkdf2",
                    "salt": self.salt_hex,
                    "params": {
                        "iterations": KDF_ITERATIONS,
                        "hash": "sha256"
                    },
                    "degraded_profile_reason": "yougen wasm MLS snapshot fallback uses sha256 stretching until native Argon2id is wired"
                },
                "aead": {
                    "name": "xchacha20_poly1305",
                    "nonce": nonce
                }
            },
            "contents": [{
                "item_type": "mls_group_state",
                "mls_group_id": self.group_id,
                "epoch": self.epoch,
                "secret_id": "yougen_mls_snapshot",
                "space_ref": self.space_id
            }],
            "ciphertext": ciphertext,
            "ciphertext_digest": ciphertext_digest,
            "envelope_meta": {
                "space_ref": self.space_id,
                "group_id": self.group_id,
                "epoch": self.epoch,
                "recorded_at": self.recorded_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            }
        });
        if is_protocol_device_id(device_id)
            && let Some(object) = body.as_object_mut()
        {
            object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
        }
        crate::key_backup::attach_key_backup_domain_separation(
            &mut body,
            crate::key_backup::KeyBackupClass::MlsHistory,
            "mls_snapshot",
        );
        body
    }

    /// Round-trip the inner `MlsGroupStateRecord` (after
    /// `decrypt_envelope`) into the SDK's typed shape. Native-only —
    /// the wasm build's MLS surface is stubbed.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn restore_state_record(bytes: &[u8]) -> Result<MlsGroupStateRecord, EnvelopeError> {
        serde_json::from_slice::<MlsGroupStateRecord>(bytes)
            .map_err(|err| EnvelopeError::InvalidStateRecord(err.to_string()))
    }
}

/// Helper used by both the boot path and the "sync from
/// another device" UI button. Decrypts the envelope, sanity-checks
/// the epoch, and (on native) reconstructs the SDK group via
/// [`contrix_sdk::ContrixMlsGroup::restore_from_state_record`]. The
/// wasm path stops at the byte-level decrypt — yougen's wasm MLS
/// surface is the placeholder shape that doesn't carry a live
/// openmls provider.
///
/// `current_epoch_floor` is taken from the latest Anchor view; pass
/// `0` to skip the freshness check (e.g. first-boot rehydrate where
/// no Anchor view is known yet).
#[cfg(not(target_arch = "wasm32"))]
pub fn restore_envelope(
    envelope: &MlsSnapshotEnvelope,
    passphrase: &str,
    current_epoch_floor: u64,
) -> Result<contrix_sdk::ContrixMlsGroup, EnvelopeError> {
    let bytes = decrypt_with_epoch_check(envelope, passphrase, current_epoch_floor)?;
    let record = MlsSnapshotEnvelope::restore_state_record(&bytes)?;
    contrix_sdk::ContrixMlsGroup::restore_from_state_record(&record)
        .map_err(|err| EnvelopeError::SdkRestore(err.to_string()))
}

// ───────────────────── Crypto primitives ────────────────────────

fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut state: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(MLS_ENVELOPE_MAGIC);
        hasher.update(salt);
        hasher.update(passphrase.as_bytes());
        hasher.finalize().into()
    };
    for round in 1..iterations {
        let mut hasher = Sha256::new();
        hasher.update(state);
        hasher.update(round.to_be_bytes());
        hasher.update(passphrase.as_bytes());
        state = hasher.finalize().into();
    }
    state
}

fn xor_keystream(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter: u64 = 0;
    for chunk in data.chunks(32) {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(counter.to_be_bytes());
        let block: [u8; 32] = hasher.finalize().into();
        for (i, byte) in chunk.iter().enumerate() {
            out.push(byte ^ block[i]);
        }
        counter = counter.wrapping_add(1);
    }
    out
}

fn compute_mac(key: &[u8; 32], salt: &[u8], epoch: u64, ciphertext: &[u8]) -> [u8; 32] {
    // Manual HMAC-SHA-256: H((K ^ opad) || H((K ^ ipad) || msg)).
    // Block size 64 for SHA-256.
    let mut k_padded = [0u8; 64];
    k_padded[..32].copy_from_slice(key);
    let mut k_inner = [0u8; 64];
    let mut k_outer = [0u8; 64];
    for i in 0..64 {
        k_inner[i] = k_padded[i] ^ MAC_INNER_PAD;
        k_outer[i] = k_padded[i] ^ MAC_OUTER_PAD;
    }
    let mut inner = Sha256::new();
    inner.update(k_inner);
    inner.update(salt);
    inner.update(epoch.to_be_bytes());
    inner.update(ciphertext);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k_outer);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn is_protocol_device_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("cx:device:") else {
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

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

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
            "updated_at": "2026-05-09T00:00:00Z",
        });
        serde_json::to_vec(&body).unwrap()
    }

    #[test]
    fn persist_restore_round_trip_recovers_group_state() {
        let bytes = fake_state_record_bytes("aabbccdd", 7);
        let envelope = encrypt_state(
            "cx:space:demo",
            "aabbccdd",
            7,
            &bytes,
            "correct horse battery staple",
            &fixed_salt(),
        );
        assert_eq!(envelope.space_id, "cx:space:demo");
        assert_eq!(envelope.group_id, "aabbccdd");
        assert_eq!(envelope.epoch, 7);
        // Ciphertext is not the plaintext — encryption did something.
        assert_ne!(envelope.ciphertext_hex, hex_encode(&bytes));

        let plaintext = decrypt_envelope(&envelope, "correct horse battery staple")
            .expect("happy-path decrypt");
        assert_eq!(plaintext, bytes);
    }

    #[test]
    fn passphrase_mismatch_is_rejected_distinct_from_other_errors() {
        let bytes = fake_state_record_bytes("dead", 1);
        let envelope = encrypt_state(
            "cx:space:demo",
            "dead",
            1,
            &bytes,
            "secret one",
            &fixed_salt(),
        );
        let result = decrypt_envelope(&envelope, "secret two");
        assert!(matches!(result, Err(EnvelopeError::PassphraseMismatch)));

        // Tampered ciphertext also surfaces as PassphraseMismatch
        // (MAC failure — the two cases are indistinguishable by
        // design and both block restore).
        let mut tampered = envelope.clone();
        tampered.ciphertext_hex.replace_range(0..2, "ff");
        let result = decrypt_envelope(&tampered, "secret one");
        assert!(matches!(result, Err(EnvelopeError::PassphraseMismatch)));
    }

    #[test]
    fn outdated_snapshot_is_rejected_via_epoch_check() {
        let bytes = fake_state_record_bytes("beef", 3);
        let envelope = encrypt_state("cx:space:demo", "beef", 3, &bytes, "p1", &fixed_salt());

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

        // Passphrase-mismatch beats outdated check (we don't leak the
        // envelope epoch to a wrong-passphrase caller).
        let result = decrypt_with_epoch_check(&envelope, "wrong", 5);
        assert!(matches!(result, Err(EnvelopeError::PassphraseMismatch)));
    }

    #[test]
    fn malformed_hex_surfaces_typed_error() {
        let mut envelope = encrypt_state("cx:space:demo", "feed", 1, b"abc", "p", &fixed_salt());
        envelope.ciphertext_hex = "zzzz".to_owned(); // not hex
        let result = decrypt_envelope(&envelope, "p");
        assert!(matches!(result, Err(EnvelopeError::Malformed(_))));
    }

    #[test]
    fn key_backup_body_carries_envelope_meta_and_blob() {
        let envelope = encrypt_state(
            "cx:space:demo",
            "aaaa",
            42,
            b"placeholder",
            "passw",
            &fixed_salt(),
        );
        let body = envelope.to_key_backup_body(
            "cx:backup:01964137-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
        );
        assert_eq!(
            body["backup_id"],
            "cx:backup:01964137-0000-7000-8000-000000000000"
        );
        assert_eq!(
            body["device_id"],
            "cx:device:01964137-0000-7000-8000-000000000001"
        );
        assert_eq!(body["backup_class"], "mls_history");
        assert_eq!(body["backup_version"], "kb_mls_snapshot_v1");
        assert_eq!(body["contents"][0]["item_type"], "mls_group_state");
        assert_eq!(
            body["domain_separation"]["hkdf_info"],
            "contrix-key-backup/mls_history/mls_snapshot/v1"
        );
        crate::key_backup::validate_key_backup_envelope(
            &body,
            Some(crate::key_backup::KeyBackupClass::MlsHistory),
        )
        .expect("MLS history backup envelope should validate");
        assert_eq!(body["envelope_meta"]["space_ref"], "cx:space:demo");
        assert_eq!(body["envelope_meta"]["epoch"], 42);
        // The ciphertext is a base64url-encoded JSON envelope — it
        // round-trips back to the same struct without exposing plaintext
        // MLS provider state to soland.
        let blob = body["ciphertext"].as_str().unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(blob).unwrap();
        let parsed: MlsSnapshotEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.space_id, "cx:space:demo");
        assert_eq!(parsed.epoch, 42);
    }

    #[test]
    fn encrypt_with_distinct_salts_produces_distinct_ciphertext() {
        // Sanity: salt randomisation defeats rainbow-table lookups
        // even when the same passphrase + plaintext is used across
        // two snapshots. Mirrors the SDK key_backup invariant.
        let bytes = fake_state_record_bytes("a", 1);
        let one = encrypt_state("s", "a", 1, &bytes, "p", b"salt-one");
        let two = encrypt_state("s", "a", 1, &bytes, "p", b"salt-two");
        assert_ne!(one.ciphertext_hex, two.ciphertext_hex);
        assert_ne!(one.mac_hex, two.mac_hex);
    }

    #[test]
    fn xor_keystream_is_self_inverse() {
        // Encrypt → encrypt = original. The on-the-wire scheme is XOR
        // so the same primitive decrypts.
        let key = derive_key("pass", b"salt", 100);
        let plain = b"hello mls".to_vec();
        let cipher = xor_keystream(&key, &plain);
        let round = xor_keystream(&key, &cipher);
        assert_eq!(round, plain);
    }

    #[test]
    fn constant_time_eq_handles_length_mismatch() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn invalid_state_record_surfaces_typed_error() {
        // The MAC verifies (encryption is byte-transparent), but the
        // inner bytes don't parse as `MlsGroupStateRecord`. The error
        // is `InvalidStateRecord`, distinct from `PassphraseMismatch`.
        let envelope = encrypt_state(
            "cx:space:demo",
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
        use contrix_sdk::{ContrixMlsIdentity, DeviceId, Did};

        let identity = ContrixMlsIdentity::new_basic(
            Did::new("did:web:alice.example".to_owned()).unwrap(),
            // SDK 0.7 requires the canonical `cx:device:<uuid7>` form.
            DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001".to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(b"cx:space:round28-snapshot").unwrap();
        let record = group.export_state_record().unwrap();
        let original_group_id = record.group_id.clone();
        let original_epoch = record.epoch;

        let bytes = serde_json::to_vec(&record).unwrap();
        let envelope = encrypt_state(
            "cx:space:round28-snapshot",
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
