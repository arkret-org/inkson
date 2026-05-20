//! Client-side crypto helpers for the Encrypted Cloud Vault recovery path.
//!
//! Spec: `crypto-media/devices-and-auth.md` §4.1 — the user's passphrase is
//! stretched on-device with Argon2id and the resulting key encrypts the
//! recovery payload (device signing key, recovery key, MLS state) with
//! XChaCha20-Poly1305 before it is uploaded to
//! `PUT /api/v1/keys/backups/{backup_id}`. The server never sees the
//! plaintext or the passphrase.
//!
//! The helpers in this module are pure — they take and return owned
//! buffers and never touch the API, the filesystem, or the DOM, so they
//! are exhaustively unit-tested below and build identically on every
//! Rust target (native + wasm32).

use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use getrandom::fill;
use sha2::{Digest, Sha256};

/// Argon2id parameters used by the Encrypted Cloud Vault. We deliberately
/// pick OWASP-recommended values that complete in a couple of seconds on a
/// typical laptop but are still memory-hard enough to make offline
/// passphrase guessing expensive:
///
/// * `m_cost` 65 536 KiB = 64 MiB
/// * `t_cost` 3 iterations
/// * `p_cost` 4 parallel lanes
/// * 32-byte output (XChaCha20-Poly1305 key)
///
/// 128 MiB / t=3 / p=4 (the value the design doc advertises) is only
/// reachable on native; the browser fails most allocations above ~64 MiB.
/// We pick the lower bound for both targets so the same parameters round-
/// trip cross-platform.
pub const VAULT_ARGON2_M_KIB: u32 = 65_536;
pub const VAULT_ARGON2_T: u32 = 3;
pub const VAULT_ARGON2_P: u32 = 4;
pub const VAULT_KDF_OUTPUT_LEN: usize = 32;

/// Length of the random salt fed to Argon2id. 16 bytes (128 bits) is the
/// argon2 crate's documented minimum and matches the OWASP guidance.
pub const VAULT_SALT_LEN: usize = 16;

/// Length of the XChaCha20-Poly1305 nonce. The X-variant takes a 24-byte
/// (192-bit) nonce, which is large enough that a random nonce is safe to
/// use without a counter.
pub const VAULT_NONCE_LEN: usize = 24;

/// Length of the high-entropy Recovery Key in bytes. 32 bytes = 256 bits
/// of entropy; encoded as four groups of 6 base32-style characters this
/// gives the user a memorable, copy-pasteable string.
pub const RECOVERY_KEY_BYTES: usize = 32;

/// Outcome of `derive_vault_kek`: the KEK plus the parameters that
/// generated it. The parameters are serialised into the backup body so
/// any future device can reproduce the KDF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKek {
    pub key: [u8; VAULT_KDF_OUTPUT_LEN],
    pub salt: [u8; VAULT_SALT_LEN],
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// Outcome of `encrypt_vault`: the ciphertext (Poly1305 tag appended by
/// the AEAD), the random nonce, and base64-encoded views of both so the
/// caller can hand them straight to the backup body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultCiphertext {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; VAULT_NONCE_LEN],
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub salt_b64: String,
    pub digest_sha256: String,
}

/// Stretch a user passphrase into a 32-byte key under Argon2id with a
/// fresh random salt. Returns the KEK alongside the salt so the caller
/// can store the salt as backup metadata.
pub fn derive_vault_kek(passphrase: &[u8]) -> Result<VaultKek> {
    let mut salt = [0u8; VAULT_SALT_LEN];
    fill(&mut salt).map_err(|err| anyhow!("salt rng: {err}"))?;
    derive_vault_kek_with_salt(passphrase, &salt)
}

/// Variant of [`derive_vault_kek`] with caller-supplied salt — used both
/// in tests (deterministic vectors) and on the recovery path when a
/// previously stored backup is being decrypted.
pub fn derive_vault_kek_with_salt(
    passphrase: &[u8],
    salt: &[u8; VAULT_SALT_LEN],
) -> Result<VaultKek> {
    let params = Params::new(VAULT_ARGON2_M_KIB, VAULT_ARGON2_T, VAULT_ARGON2_P, None)
        .map_err(|err| anyhow!("argon2 params: {err}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; VAULT_KDF_OUTPUT_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|err| anyhow!("argon2 hash: {err}"))?;
    Ok(VaultKek {
        key,
        salt: *salt,
        m_kib: VAULT_ARGON2_M_KIB,
        t: VAULT_ARGON2_T,
        p: VAULT_ARGON2_P,
    })
}

/// Encrypt the vault plaintext under the KEK with XChaCha20-Poly1305 and
/// a fresh random nonce. The returned struct carries everything the
/// recovery backup body needs (ciphertext, nonce, salt, sha256 digest).
pub fn encrypt_vault(kek: &VaultKek, plaintext: &[u8]) -> Result<VaultCiphertext> {
    let cipher = XChaCha20Poly1305::new((&kek.key).into());
    let mut nonce_bytes = [0u8; VAULT_NONCE_LEN];
    fill(&mut nonce_bytes).map_err(|err| anyhow!("nonce rng: {err}"))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|err| anyhow!("xchacha20poly1305 encrypt: {err}"))?;
    let digest = Sha256::digest(&ciphertext);
    Ok(VaultCiphertext {
        ciphertext_b64: B64.encode(&ciphertext),
        nonce_b64: B64.encode(nonce_bytes),
        salt_b64: B64.encode(kek.salt),
        digest_sha256: format!("sha256:{}", hex_lower(&digest)),
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// Decrypt a previously produced vault ciphertext. Used by tests today
/// and by the future "restore" flow tomorrow. Returns an error if the
/// passphrase is wrong (AEAD tag mismatch) or if any input is malformed.
pub fn decrypt_vault(
    passphrase: &[u8],
    salt_b64: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>> {
    let salt_bytes = B64
        .decode(salt_b64.trim_end_matches('='))
        .context("salt base64")?;
    let salt: [u8; VAULT_SALT_LEN] = salt_bytes
        .try_into()
        .map_err(|_| anyhow!("salt must be {VAULT_SALT_LEN} bytes"))?;
    let nonce_bytes = B64
        .decode(nonce_b64.trim_end_matches('='))
        .context("nonce base64")?;
    let nonce_array: [u8; VAULT_NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow!("nonce must be {VAULT_NONCE_LEN} bytes"))?;
    let ciphertext = B64
        .decode(ciphertext_b64.trim_end_matches('='))
        .context("ciphertext base64")?;
    let kek = derive_vault_kek_with_salt(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&kek.key).into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce_array), ciphertext.as_slice())
        .map_err(|_| anyhow!("vault decrypt failed: wrong passphrase or corrupt ciphertext"))?;
    Ok(plaintext)
}

/// Generate a fresh Recovery Key as a human-readable string: 6 groups of
/// 5-6 characters drawn from a Crockford-style alphabet (0-9 + A-Z minus
/// `I/L/O/U` to avoid look-alikes). 30 characters of base32 ≈ 150 bits
/// of entropy, which is plenty for a fallback secret.
pub fn generate_recovery_key() -> Result<String> {
    let mut bytes = [0u8; RECOVERY_KEY_BYTES];
    fill(&mut bytes).map_err(|err| anyhow!("recovery key rng: {err}"))?;
    Ok(format_recovery_key(&bytes))
}

/// Render the recovery-key string from raw bytes — split out so the
/// generator is testable without consuming entropy.
pub fn format_recovery_key(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    let mut groups: Vec<String> = Vec::with_capacity(6);
    let mut current = String::with_capacity(5);
    let mut emitted = 0usize;
    for &b in bytes {
        bits = (bits << 8) | u64::from(b);
        nbits += 8;
        while nbits >= 5 && emitted < 30 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 0x1F) as usize;
            current.push(ALPHABET[idx] as char);
            emitted += 1;
            if current.len() == 5 {
                groups.push(std::mem::take(&mut current));
            }
        }
        if emitted >= 30 {
            break;
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups.join("-")
}

/// SHA-256 the recovery key (UTF-8) and return `"sha256:<hex>"`. We only
/// persist the digest on disk so the plaintext is gone the moment the
/// user dismisses the "copy / print" affordance.
pub fn fingerprint_recovery_key(recovery_key: &str) -> String {
    let digest = Sha256::digest(recovery_key.as_bytes());
    format!("sha256:{}", hex_lower(&digest))
}

/// Round R2/R3 (T15) — OOB code entry validation.
///
/// The OOB code-entry field MUST accept both wire forms (see
/// `crypto-media/device-lifecycle.md §6.2`, Round R2/R3 close-out):
///
/// 1. **Direct-handle form** — ≥22 characters of base32 drawn from the
///    Crockford-style alphabet (`0-9` + `A-Z` minus the look-alike
///    pair `I/L/0/1/O`). This is what the device-handoff QR encodes.
/// 2. **Lookup form** — shorter, server-determined opaque code (the
///    server returns `oob_code_kind: "lookup"` and resolves it
///    against a side table). Length / charset is server-defined; the
///    client only normalises whitespace + uppercases A-Z so the user
///    can paste the code with the casing they were emailed.
///
/// The validator returns the classification so the calling UI can
/// dispatch to the right server endpoint. Per `oob_code_kind`, the
/// client MUST NOT reveal *which* form failed — the rate-limited
/// failure surface returns the generic
/// `"code invalid or expired"` after 3 wrong attempts (see
/// [`OobCodeAttemptTracker`] below).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OobCodeKind {
    /// ≥22-char Crockford-base32 (excluding I/L/0/1/O).
    DirectHandle,
    /// Shorter opaque lookup code; server-resolved.
    Lookup,
}

/// Crockford-base32 alphabet (Round R2/R3 OOB direct-handle form). 28
/// glyphs after stripping the four ambiguous pairs `I`, `L`, `0`, `1`,
/// `O`. Hex case A-Z accepted; the user may paste lowercase and the
/// validator uppercases before checking.
pub const OOB_DIRECT_HANDLE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Round R2/R3 (T15) — minimum length of the direct-handle form. 22
/// characters of base32 ≈ 110 bits of entropy, matching the spec's
/// device-handoff floor.
pub const OOB_DIRECT_HANDLE_MIN_LEN: usize = 22;

/// Classify an OOB code entry. Returns `None` when the input fails both
/// forms (caller MUST surface a generic error per the
/// 3-attempt-then-generic rule).
pub fn classify_oob_code(input: &str) -> Option<OobCodeKind> {
    let normalised: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalised.is_empty() {
        return None;
    }
    if normalised.len() >= OOB_DIRECT_HANDLE_MIN_LEN
        && normalised
            .bytes()
            .all(|b| OOB_DIRECT_HANDLE_ALPHABET.contains(&b))
    {
        return Some(OobCodeKind::DirectHandle);
    }
    // Lookup form: server decides validity. Locally we only require a
    // non-empty token that doesn't contain control / whitespace
    // characters. The bound (>=4 chars) prevents the dispatcher from
    // sending obviously-junk single-character codes.
    if normalised.len() >= 4 && normalised.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Some(OobCodeKind::Lookup);
    }
    None
}

/// Round R2/R3 (T15) — local 3-strike attempt tracker for the OOB lookup
/// form. After the third wrong attempt, callers MUST surface the generic
/// "code invalid or expired" message and refuse to reveal whether the
/// code's form, length, or expiry was the cause. The tracker is intended
/// to be embedded in a Dioxus signal so it survives across keystrokes
/// without leaking attempt count into the wire payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OobCodeAttemptTracker {
    pub wrong_attempts: u8,
}

impl OobCodeAttemptTracker {
    pub const MAX_ATTEMPTS: u8 = 3;

    /// Note a server-rejected attempt. Returns `true` once the tracker
    /// reached the generic-error threshold so the UI knows to switch
    /// messaging.
    pub fn note_wrong(&mut self) -> bool {
        self.wrong_attempts = self.wrong_attempts.saturating_add(1);
        self.is_locked_to_generic_error()
    }

    /// True once the user has burned their 3 attempts on the lookup
    /// form. Caller must show the generic message and stop dispatching
    /// to the server until the user resets the field.
    pub fn is_locked_to_generic_error(&self) -> bool {
        self.wrong_attempts >= Self::MAX_ATTEMPTS
    }

    /// Reset after a successful exchange or when the user types a new
    /// candidate.
    pub fn reset(&mut self) {
        self.wrong_attempts = 0;
    }
}

/// Heuristic passphrase strength on a 0..=5 scale, mirroring the
/// "Passphrase strength" tile in the Recovery view. Pure function so the
/// UI can call it on every keystroke without touching state.
pub fn estimate_passphrase_strength(passphrase: &str) -> u8 {
    if passphrase.is_empty() {
        return 0;
    }
    let mut score = 0i32;
    let len = passphrase.chars().count();
    score += match len {
        0..=7 => 0,
        8..=11 => 1,
        12..=15 => 2,
        16..=23 => 3,
        _ => 4,
    };
    let mut classes = 0;
    if passphrase.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 1;
    }
    if passphrase.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 1;
    }
    if passphrase.chars().any(|c| c.is_ascii_digit()) {
        classes += 1;
    }
    if passphrase.chars().any(|c| !c.is_ascii_alphanumeric()) {
        classes += 1;
    }
    score += match classes {
        4 => 1,
        3 => 1,
        _ => 0,
    };
    score.clamp(0, 5) as u8
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oob_direct_handle_form_accepts_22_plus_chars_no_lookalikes() {
        // 22-char Crockford-base32 string with no I/L/0/1/O.
        let candidate = "23456789ABCDEFGHJKMNPQ";
        assert_eq!(candidate.len(), 22);
        assert_eq!(
            classify_oob_code(candidate),
            Some(OobCodeKind::DirectHandle),
        );
    }

    #[test]
    fn oob_direct_handle_form_rejects_lookalikes() {
        // Contains 'I' which is excluded from the Crockford alphabet.
        let candidate = "234567I9ABCDEFGHJKMNPQ";
        // Length is 22, but contains an excluded glyph — falls through
        // to lookup form, which accepts shorter alphanumerics. The
        // direct-handle form is NOT selected.
        assert_ne!(
            classify_oob_code(candidate),
            Some(OobCodeKind::DirectHandle),
        );
    }

    #[test]
    fn oob_lookup_form_accepts_short_codes() {
        assert_eq!(classify_oob_code("AB7K"), Some(OobCodeKind::Lookup));
        assert_eq!(classify_oob_code("xyz789"), Some(OobCodeKind::Lookup));
    }

    #[test]
    fn oob_rejects_empty_and_too_short() {
        assert_eq!(classify_oob_code(""), None);
        assert_eq!(classify_oob_code("AB"), None);
    }

    #[test]
    fn oob_attempt_tracker_locks_after_three_strikes() {
        let mut t = OobCodeAttemptTracker::default();
        assert!(!t.note_wrong());
        assert!(!t.note_wrong());
        assert!(t.note_wrong());
        assert!(t.is_locked_to_generic_error());
        t.reset();
        assert!(!t.is_locked_to_generic_error());
    }

    #[test]
    fn argon2id_is_deterministic_under_fixed_salt() {
        let salt = [42u8; VAULT_SALT_LEN];
        let a = derive_vault_kek_with_salt(b"correct horse battery staple", &salt).unwrap();
        let b = derive_vault_kek_with_salt(b"correct horse battery staple", &salt).unwrap();
        assert_eq!(a.key, b.key, "same passphrase + salt must yield same key");
        assert_eq!(a.salt, b.salt);
        assert_eq!(a.m_kib, VAULT_ARGON2_M_KIB);
        assert_eq!(a.t, VAULT_ARGON2_T);
        assert_eq!(a.p, VAULT_ARGON2_P);
    }

    #[test]
    fn argon2id_differs_under_different_salt() {
        let s1 = [1u8; VAULT_SALT_LEN];
        let s2 = [2u8; VAULT_SALT_LEN];
        let a = derive_vault_kek_with_salt(b"hunter2", &s1).unwrap();
        let b = derive_vault_kek_with_salt(b"hunter2", &s2).unwrap();
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let kek = derive_vault_kek_with_salt(b"open sesame", &[7u8; VAULT_SALT_LEN]).unwrap();
        let plaintext = br#"{"device_sk":"opaque","recovery_key_digest":"sha256:..."}"#;
        let ct = encrypt_vault(&kek, plaintext).unwrap();
        let recovered = decrypt_vault(
            b"open sesame",
            &ct.salt_b64,
            &ct.nonce_b64,
            &ct.ciphertext_b64,
        )
        .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_passphrase() {
        let kek = derive_vault_kek_with_salt(b"first", &[3u8; VAULT_SALT_LEN]).unwrap();
        let ct = encrypt_vault(&kek, b"payload").unwrap();
        let err =
            decrypt_vault(b"second", &ct.salt_b64, &ct.nonce_b64, &ct.ciphertext_b64).unwrap_err();
        assert!(err.to_string().contains("vault decrypt failed"));
    }

    #[test]
    fn ciphertext_digest_matches_sha256_of_raw_bytes() {
        let kek = derive_vault_kek_with_salt(b"pp", &[9u8; VAULT_SALT_LEN]).unwrap();
        let ct = encrypt_vault(&kek, b"hello world").unwrap();
        let digest = Sha256::digest(&ct.ciphertext);
        assert_eq!(ct.digest_sha256, format!("sha256:{}", hex_lower(&digest)));
    }

    #[test]
    fn nonce_and_salt_decode_cleanly_from_emitted_b64() {
        let kek = derive_vault_kek_with_salt(b"pp", &[12u8; VAULT_SALT_LEN]).unwrap();
        let ct = encrypt_vault(&kek, b"x").unwrap();
        let salt_back = B64.decode(ct.salt_b64.trim_end_matches('=')).unwrap();
        let nonce_back = B64.decode(ct.nonce_b64.trim_end_matches('=')).unwrap();
        assert_eq!(salt_back.len(), VAULT_SALT_LEN);
        assert_eq!(nonce_back.len(), VAULT_NONCE_LEN);
        assert_eq!(salt_back, kek.salt);
        assert_eq!(nonce_back, ct.nonce);
    }

    #[test]
    fn recovery_key_format_is_grouped() {
        let key = format_recovery_key(&[0xFFu8; RECOVERY_KEY_BYTES]);
        let groups: Vec<&str> = key.split('-').collect();
        assert!(
            groups.len() >= 5,
            "expected 5-6 dash-delimited groups, got: {key}"
        );
        for g in &groups {
            assert!(!g.is_empty());
            assert!(g.chars().all(|c| {
                let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
                alphabet.contains(&(c as u8))
            }));
        }
    }

    #[test]
    fn recovery_key_format_differs_per_input() {
        let a = format_recovery_key(&[0x00u8; RECOVERY_KEY_BYTES]);
        let b = format_recovery_key(&[0xFFu8; RECOVERY_KEY_BYTES]);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_is_stable_and_hex() {
        let fp = fingerprint_recovery_key("EAGLE-HARP-SUNDAY-ROOK-9F2C-Q1A0");
        assert!(fp.starts_with("sha256:"));
        assert_eq!(fp.len(), "sha256:".len() + 64);
        assert!(
            fp.chars()
                .skip("sha256:".len())
                .all(|c| c.is_ascii_hexdigit())
        );
        let fp2 = fingerprint_recovery_key("EAGLE-HARP-SUNDAY-ROOK-9F2C-Q1A0");
        assert_eq!(fp, fp2);
    }

    #[test]
    fn passphrase_strength_grows_with_length_and_classes() {
        assert_eq!(estimate_passphrase_strength(""), 0);
        assert!(
            estimate_passphrase_strength("short")
                < estimate_passphrase_strength("longerpassphrase")
        );
        assert!(
            estimate_passphrase_strength("alllowercaseonly")
                < estimate_passphrase_strength("Alllowercaseonly1!")
        );
        // 24+ chars across all four character classes saturates the scorer.
        assert_eq!(
            estimate_passphrase_strength("Correct horse battery staple 9!"),
            5
        );
    }

    #[test]
    fn live_kek_and_decrypt_path_works_with_random_salt() {
        // Smoke test for the "real" entry point that uses getrandom for the salt.
        let kek = derive_vault_kek(b"random-salt-passphrase").unwrap();
        let ct = encrypt_vault(&kek, b"hello").unwrap();
        let plain = decrypt_vault(
            b"random-salt-passphrase",
            &ct.salt_b64,
            &ct.nonce_b64,
            &ct.ciphertext_b64,
        )
        .unwrap();
        assert_eq!(plain, b"hello");
    }
}
