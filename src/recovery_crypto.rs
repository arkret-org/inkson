//! Client-side crypto helpers for the key-backup recovery path.
//!
//! Spec: `crypto-media/devices-and-auth.md` §4.1 — the recovery credential
//! (the normalized 24-word Recovery Key, or an internal secret such as the
//! account MLS secret) is stretched on-device with Argon2id and the resulting
//! KEK encrypts the backup payload with XChaCha20-Poly1305 before it is
//! uploaded to `PUT /_cokret/self/keys/backups/{backup_id}`. The server never
//! sees the plaintext or the credential. (`VAULT_*` constant names are kept —
//! they describe the sealed-envelope "vault" primitive, not the removed
//! vault-passphrase UI.)
//!
//! The helpers in this module are pure — they take and return owned
//! buffers and never touch the API, the filesystem, or the DOM, so they
//! are exhaustively unit-tested below and build identically on every
//! Rust target (native + wasm32).

use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::fill;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Argon2id parameters used by the key-backup KEK derivation. We deliberately
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
/// of entropy; encoded as a 24-word BIP-39 mnemonic for user custody.
pub const RECOVERY_KEY_BYTES: usize = 32;

/// WebAuthn PRF outputs are SHA-256-sized secrets. We treat them as wrapping
/// key material only: the 24-word Recovery Key remains the offline root.
pub const PASSKEY_PRF_OUTPUT_LEN: usize = 32;

/// Random salt supplied to the WebAuthn PRF extension and reused as HKDF salt
/// for the local Recovery Key wrapper.
pub const PASSKEY_WRAP_SALT_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length for the local passkey wrapper.
pub const PASSKEY_WRAP_NONCE_LEN: usize = 24;

/// Length of the producer-generated `nonce_salt` (key-management.md §7.5: "至少
/// 128-bit 随机值"). Mixed into the deterministic nonce transcript so duplicate
/// business-metadata tuples cannot collide nonces.
pub const VAULT_NONCE_SALT_LEN: usize = 16;

/// AEAD identifiers carried on the wire (spec §7.5 / §12 example).
pub const VAULT_AEAD_NAME: &str = "xchacha20_poly1305";
pub const VAULT_AEAD_PROFILE: &str = "ck.aead.xchacha20_poly1305.v1";

const HKDF_COMMITMENT_INFO: &[u8] = b"cokret-key-backup-commitment-v1";
const HKDF_NONCE_INFO: &[u8] = b"cokret-key-backup-aead-nonce-v1";
const HKDF_PASSKEY_WRAP_INFO: &[u8] = b"cokret-recovery-passkey-wrap-v1";

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

impl Drop for VaultKek {
    /// R16: the Argon2id root key is the master secret behind every vault
    /// subkey; wipe it on drop (including dropped `Clone`s) so it doesn't
    /// outlive its use in freed memory. The salt / params are non-secret.
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Envelope metadata that the spec §7.5 nonce transcript and §7.1 AEAD AAD bind
/// to. The envelope builder owns these strings; the crypto derives the
/// domain-isolated AEAD key, the deterministic nonce, and the key commitment
/// from them. `aad_canonical` is the canonical-JSON bytes of the envelope's
/// `domain_separation.aead_aad` object (single source of truth for the AAD, so
/// encrypt and decrypt bind byte-identical associated data).
#[derive(Clone, Copy)]
pub struct VaultSealContext<'a> {
    pub backup_id: &'a str,
    pub actor_id: &'a str,
    pub device_id: &'a str,
    pub backup_class: &'a str,
    pub subdomain: &'a str,
    pub backup_version: &'a str,
    pub created_at: &'a str,
    pub aad_canonical: &'a [u8],
}

/// Outcome of [`seal_vault`]: base64url ciphertext + the deterministic
/// nonce/salt/nonce_salt and the `key_commitment`, ready to drop into a
/// `ck.schema.key_backup.v1` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSealed {
    pub ciphertext_b64: String,
    pub ciphertext_digest: String,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub nonce_salt_b64: String,
    pub key_commitment: String,
}

/// Local passkey/WebAuthn PRF wrapper output. This is not a
/// `ck.schema.key_backup.v1` wire envelope and deliberately does not introduce
/// a new `recipient_method`; it is a browser-local convenience wrapper for the
/// current 24-word Recovery Key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyWrappedRecoveryKey {
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub ciphertext_digest: String,
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

/// HKDF-Expand the Argon2id root key into a 32-byte domain subkey
/// (`HKDF(root, info)`, salt=none per key-management.md §7.1/§7.5).
fn hkdf_subkey(root: &[u8; VAULT_KDF_OUTPUT_LEN], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, root);
    // R16: wrap the derived subkey so it zeroizes on drop at every call site.
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut())
        .map_err(|err| anyhow!("hkdf expand: {err}"))?;
    Ok(out)
}

/// Domain-isolated AEAD wrap key: `HKDF(root, "cokret-key-backup/<class>/<subdomain>/v1")`.
fn vault_aead_key(
    root: &[u8; VAULT_KDF_OUTPUT_LEN],
    backup_class: &str,
    subdomain: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let info = format!("cokret-key-backup/{backup_class}/{subdomain}/v1");
    hkdf_subkey(root, info.as_bytes())
}

/// `key_commitment = SHA256(HKDF(root, "cokret-key-backup-commitment-v1"))`
/// (key-management.md §7.5). Lets a recovering client reject a wrong passphrase
/// before touching the ciphertext.
pub fn vault_key_commitment(root: &VaultKek) -> Result<String> {
    let commitment_key = hkdf_subkey(&root.key, HKDF_COMMITMENT_INFO)?;
    Ok(format!(
        "sha256:{}",
        hex_lower(&Sha256::digest(&*commitment_key))
    ))
}

/// Deterministic AEAD nonce per key-management.md §7.5:
/// `HMAC-SHA256(HKDF(root,"...-aead-nonce-v1"), canonical_json(transcript))[0:24]`.
fn vault_nonce(
    root: &VaultKek,
    ctx: &VaultSealContext<'_>,
    nonce_salt_b64: &str,
) -> Result<[u8; VAULT_NONCE_LEN]> {
    let nonce_key = hkdf_subkey(&root.key, HKDF_NONCE_INFO)?;
    let transcript = serde_json::json!({
        "backup_id": ctx.backup_id,
        "actor_id": ctx.actor_id,
        "device_id": ctx.device_id,
        "backup_class": ctx.backup_class,
        "backup_version": ctx.backup_version,
        "created_at": ctx.created_at,
        "aead": VAULT_AEAD_NAME,
        "aead_profile": VAULT_AEAD_PROFILE,
        "nonce_salt": nonce_salt_b64,
    });
    let bytes = crate::canonical::canonical_json_bytes(&transcript)
        .map_err(|err| anyhow!("nonce transcript canonical json: {err}"))?;
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(&*nonce_key)
        .map_err(|err| anyhow!("hmac key: {err}"))?;
    mac.update(&bytes);
    let tag = mac.finalize().into_bytes();
    let mut nonce = [0u8; VAULT_NONCE_LEN];
    nonce.copy_from_slice(&tag[..VAULT_NONCE_LEN]);
    Ok(nonce)
}

/// Spec §7.5 seal: domain-isolated HKDF AEAD key, deterministic nonce derived
/// from a fresh `nonce_salt`, AAD bound to the envelope metadata, and a
/// `key_commitment` for wrong-passphrase fail-fast. Replaces the old
/// direct-Argon2-key + random-nonce + no-AAD path.
pub fn seal_vault(
    root: &VaultKek,
    ctx: &VaultSealContext<'_>,
    plaintext: &[u8],
) -> Result<VaultSealed> {
    let mut nonce_salt = [0u8; VAULT_NONCE_SALT_LEN];
    fill(&mut nonce_salt).map_err(|err| anyhow!("nonce_salt rng: {err}"))?;
    let nonce_salt_b64 = B64.encode(nonce_salt);

    let aead_key = vault_aead_key(&root.key, ctx.backup_class, ctx.subdomain)?;
    let nonce = vault_nonce(root, ctx, &nonce_salt_b64)?;
    let cipher = XChaCha20Poly1305::new((&*aead_key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ctx.aad_canonical,
            },
        )
        .map_err(|err| anyhow!("xchacha20poly1305 encrypt: {err}"))?;
    let digest = Sha256::digest(&ciphertext);
    Ok(VaultSealed {
        ciphertext_b64: B64.encode(&ciphertext),
        ciphertext_digest: format!("sha256:{}", hex_lower(&digest)),
        salt_b64: B64.encode(root.salt),
        nonce_b64: B64.encode(nonce),
        nonce_salt_b64,
        key_commitment: vault_key_commitment(root)?,
    })
}

/// Spec §7.5 open: re-derive the root from the passphrase + salt, verify
/// `key_commitment` (wrong-passphrase fail-fast), recompute and check the
/// deterministic nonce, then AEAD-decrypt with the bound AAD. Any mismatch is a
/// hard error.
#[allow(clippy::too_many_arguments)]
pub fn open_vault(
    passphrase: &[u8],
    ctx: &VaultSealContext<'_>,
    salt_b64: &str,
    nonce_b64: &str,
    nonce_salt_b64: &str,
    key_commitment: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>> {
    let salt_bytes = B64
        .decode(salt_b64.trim_end_matches('='))
        .context("salt base64")?;
    let salt: [u8; VAULT_SALT_LEN] = salt_bytes
        .try_into()
        .map_err(|_| anyhow!("salt must be {VAULT_SALT_LEN} bytes"))?;
    let root = derive_vault_kek_with_salt(passphrase, &salt)?;

    // Wrong-passphrase fail-fast via key_commitment before any AEAD work.
    if !key_commitment.is_empty() && vault_key_commitment(&root)? != key_commitment {
        return Err(anyhow!(
            "vault decrypt failed: key_commitment mismatch (wrong passphrase)"
        ));
    }

    // Receiver MUST recompute the deterministic nonce and reject mismatches.
    let expected_nonce = vault_nonce(&root, ctx, nonce_salt_b64)?;
    let nonce_bytes = B64
        .decode(nonce_b64.trim_end_matches('='))
        .context("nonce base64")?;
    if nonce_bytes != expected_nonce {
        return Err(anyhow!(
            "vault decrypt failed: nonce does not match the spec transcript"
        ));
    }

    let aead_key = vault_aead_key(&root.key, ctx.backup_class, ctx.subdomain)?;
    let ciphertext = B64
        .decode(ciphertext_b64.trim_end_matches('='))
        .context("ciphertext base64")?;
    let cipher = XChaCha20Poly1305::new((&*aead_key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&expected_nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad: ctx.aad_canonical,
            },
        )
        .map_err(|_| anyhow!("vault decrypt failed: wrong passphrase or corrupt ciphertext"))?;
    // R16: the recovered plaintext is the unwrapped backup payload (device
    // signing key / recovery key / MLS state). The return type is kept as
    // `Vec<u8>` to avoid churning every caller; callers in `key_backup` /
    // `mls::account_recovery` SHOULD wrap it in `Zeroizing` once they own it.
    // Internal subkeys (`aead_key`, HKDF subkeys, the `VaultKek` root) all
    // zeroize on drop here.
    Ok(plaintext)
}

/// Generate a fresh Recovery Key as a BIP-39 English mnemonic.
///
/// We use 32 bytes of OS randomness, encoded as 24 words with the BIP-39
/// checksum. The returned string is lowercase words separated by single spaces.
/// This is easier to write down while keeping the same 256-bit secret material.
pub fn generate_recovery_key() -> Result<String> {
    let mut bytes = [0u8; RECOVERY_KEY_BYTES];
    fill(&mut bytes).map_err(|err| anyhow!("recovery key rng: {err}"))?;
    Ok(format_recovery_key(&bytes))
}

/// Render the recovery-key mnemonic from raw bytes — split out so the
/// generator is testable without consuming entropy.
pub fn format_recovery_key(bytes: &[u8]) -> String {
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, bytes)
        .map(|mnemonic| mnemonic.words().collect::<Vec<_>>().join(" "))
        .expect("RECOVERY_KEY_BYTES is valid BIP-39 entropy length")
}

/// Normalize user-entered recovery-key material before using it as a KEK
/// source.
///
/// Only the current 24-word BIP-39 Recovery Key format is accepted.
/// Valid phrases are canonicalized to lowercase words with single spaces.
pub fn normalize_recovery_key_input(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let collapsed = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    if collapsed.split_whitespace().count() != 24 {
        return None;
    }

    let mnemonic_candidate = collapsed.to_ascii_lowercase();
    let mnemonic =
        bip39::Mnemonic::parse_in(bip39::Language::English, mnemonic_candidate.as_str()).ok()?;
    Some(mnemonic.words().collect::<Vec<_>>().join(" "))
}

/// SHA-256 the recovery key (UTF-8) and return `"sha256:<hex>"`. We only
/// persist the digest on disk so the plaintext is gone the moment the
/// user dismisses the "copy / print" affordance.
pub fn fingerprint_recovery_key(recovery_key: &str) -> String {
    let canonical = normalize_recovery_key_input(recovery_key)
        .expect("recovery key fingerprint requires a valid 24-word BIP-39 key");
    let digest = Sha256::digest(canonical.as_bytes());
    format!("sha256:{}", hex_lower(&digest))
}

/// Generate the random salt passed to the WebAuthn PRF extension. The salt is
/// public metadata; the authenticator-specific PRF output is the secret.
pub fn generate_passkey_wrap_salt() -> Result<[u8; PASSKEY_WRAP_SALT_LEN]> {
    let mut salt = [0u8; PASSKEY_WRAP_SALT_LEN];
    fill(&mut salt).map_err(|err| anyhow!("passkey wrap salt rng: {err}"))?;
    Ok(salt)
}

fn passkey_wrap_key(
    prf_output: &[u8],
    salt: &[u8; PASSKEY_WRAP_SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>> {
    if prf_output.len() != PASSKEY_PRF_OUTPUT_LEN {
        return Err(anyhow!(
            "passkey PRF output must be {PASSKEY_PRF_OUTPUT_LEN} bytes"
        ));
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), prf_output);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_PASSKEY_WRAP_INFO, out.as_mut())
        .map_err(|err| anyhow!("passkey wrap hkdf expand: {err}"))?;
    Ok(out)
}

/// Wrap a valid 24-word Recovery Key with a WebAuthn PRF output. Callers pass a
/// canonical AAD transcript that binds account id, credential id, rp id, wrap
/// id, and recovery-key fingerprint.
pub fn seal_recovery_key_with_passkey_prf(
    recovery_key: &str,
    prf_output: &[u8],
    salt: &[u8; PASSKEY_WRAP_SALT_LEN],
    aad: &[u8],
) -> Result<PasskeyWrappedRecoveryKey> {
    let canonical = normalize_recovery_key_input(recovery_key)
        .ok_or_else(|| anyhow!("passkey wrapper requires a valid 24-word recovery key"))?;
    let mut nonce = [0u8; PASSKEY_WRAP_NONCE_LEN];
    fill(&mut nonce).map_err(|err| anyhow!("passkey wrap nonce rng: {err}"))?;
    let key = passkey_wrap_key(prf_output, salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: canonical.as_bytes(),
                aad,
            },
        )
        .map_err(|err| anyhow!("passkey recovery key encrypt: {err}"))?;
    let digest = Sha256::digest(&ciphertext);
    Ok(PasskeyWrappedRecoveryKey {
        salt_b64: B64.encode(salt),
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(&ciphertext),
        ciphertext_digest: format!("sha256:{}", hex_lower(&digest)),
    })
}

/// Open a local passkey/WebAuthn PRF wrapper and return the canonical 24-word
/// Recovery Key. Any wrong PRF output, wrong AAD, or malformed phrase fails.
pub fn open_recovery_key_with_passkey_prf(
    prf_output: &[u8],
    salt_b64: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
    aad: &[u8],
) -> Result<String> {
    let salt_bytes = B64
        .decode(salt_b64.trim_end_matches('='))
        .context("passkey wrap salt base64")?;
    let salt: [u8; PASSKEY_WRAP_SALT_LEN] = salt_bytes
        .try_into()
        .map_err(|_| anyhow!("passkey wrap salt must be {PASSKEY_WRAP_SALT_LEN} bytes"))?;
    let nonce_bytes = B64
        .decode(nonce_b64.trim_end_matches('='))
        .context("passkey wrap nonce base64")?;
    let nonce: [u8; PASSKEY_WRAP_NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow!("passkey wrap nonce must be {PASSKEY_WRAP_NONCE_LEN} bytes"))?;
    let ciphertext = B64
        .decode(ciphertext_b64.trim_end_matches('='))
        .context("passkey wrap ciphertext base64")?;
    let key = passkey_wrap_key(prf_output, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| anyhow!("passkey recovery key decrypt failed"))?;
    let phrase = String::from_utf8(plaintext).context("passkey recovery key utf8")?;
    normalize_recovery_key_input(&phrase)
        .ok_or_else(|| anyhow!("passkey wrapper decrypted an invalid recovery key"))
}

/// Round R2/R3 (T15) — OOB code entry validation.
///
/// The OOB code-entry field MUST accept both wire forms (see
/// `crypto-media/device-lifecycle.md §6.2`, Round R2/R3 close-out):
///
/// 1. **Direct-handle form** — ≥22 characters of base32 drawn from the Crockford-style alphabet
///    (`0-9` + `A-Z` minus the look-alike pair `I/L/0/1/O`). This is what the device-handoff QR
///    encodes.
/// 2. **Lookup form** — shorter, server-determined opaque code (the server returns `oob_code_kind:
///    "lookup"` and resolves it against a side table). Length / charset is server-defined; the
///    client only normalises whitespace + uppercases A-Z so the user can paste the code with the
///    casing they were emailed.
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

fn hex_lower(bytes: &[u8]) -> String {
    crate::canonical::hex_encode(bytes)
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

    fn test_ctx<'a>(aad: &'a [u8]) -> VaultSealContext<'a> {
        VaultSealContext {
            backup_id: "ck:backup:01964137-0000-7000-8000-00000000beef",
            actor_id: "did:web:alice.example",
            device_id: "ck:device:01964137-0000-7000-8000-000000000001",
            backup_class: "secret_storage",
            subdomain: "recovery_vault",
            backup_version: "kb_1",
            created_at: "2026-06-02T00:00:00Z",
            aad_canonical: aad,
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let root = derive_vault_kek_with_salt(b"open sesame", &[7u8; VAULT_SALT_LEN]).unwrap();
        let aad = br#"{"backup_class":"secret_storage"}"#;
        let ctx = test_ctx(aad);
        let plaintext = br#"{"device_sk":"opaque"}"#;
        let sealed = seal_vault(&root, &ctx, plaintext).unwrap();
        let recovered = open_vault(
            b"open sesame",
            &ctx,
            &sealed.salt_b64,
            &sealed.nonce_b64,
            &sealed.nonce_salt_b64,
            &sealed.key_commitment,
            &sealed.ciphertext_b64,
        )
        .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn open_rejects_wrong_passphrase_via_commitment() {
        let root = derive_vault_kek_with_salt(b"first", &[3u8; VAULT_SALT_LEN]).unwrap();
        let aad = b"{}";
        let ctx = test_ctx(aad);
        let sealed = seal_vault(&root, &ctx, b"payload").unwrap();
        let err = open_vault(
            b"second",
            &ctx,
            &sealed.salt_b64,
            &sealed.nonce_b64,
            &sealed.nonce_salt_b64,
            &sealed.key_commitment,
            &sealed.ciphertext_b64,
        )
        .unwrap_err();
        assert!(err.to_string().contains("key_commitment mismatch"));
    }

    #[test]
    fn open_rejects_aad_tamper() {
        let root = derive_vault_kek_with_salt(b"pp", &[5u8; VAULT_SALT_LEN]).unwrap();
        let ctx = test_ctx(b"{\"backup_class\":\"secret_storage\"}");
        let sealed = seal_vault(&root, &ctx, b"secret").unwrap();
        // Same passphrase + nonce, but a different AAD must fail the AEAD tag.
        let tampered = test_ctx(b"{\"backup_class\":\"did_recovery\"}");
        let err = open_vault(
            b"pp",
            &tampered,
            &sealed.salt_b64,
            &sealed.nonce_b64,
            &sealed.nonce_salt_b64,
            &sealed.key_commitment,
            &sealed.ciphertext_b64,
        )
        .unwrap_err();
        assert!(err.to_string().contains("vault decrypt failed"));
    }

    #[test]
    fn nonce_is_deterministic_from_transcript() {
        let root = derive_vault_kek_with_salt(b"pp", &[9u8; VAULT_SALT_LEN]).unwrap();
        let ctx = test_ctx(b"{}");
        let n1 = vault_nonce(&root, &ctx, "c2FsdA").unwrap();
        let n2 = vault_nonce(&root, &ctx, "c2FsdA").unwrap();
        assert_eq!(n1, n2, "same transcript + nonce_salt must yield same nonce");
        let n3 = vault_nonce(&root, &ctx, "ZGlmZg").unwrap();
        assert_ne!(n1, n3, "different nonce_salt must change the nonce");
    }

    #[test]
    fn key_commitment_is_stable_and_passphrase_bound() {
        let a = derive_vault_kek_with_salt(b"pp", &[1u8; VAULT_SALT_LEN]).unwrap();
        let b = derive_vault_kek_with_salt(b"pp", &[1u8; VAULT_SALT_LEN]).unwrap();
        let c = derive_vault_kek_with_salt(b"other", &[1u8; VAULT_SALT_LEN]).unwrap();
        assert_eq!(
            vault_key_commitment(&a).unwrap(),
            vault_key_commitment(&b).unwrap()
        );
        assert_ne!(
            vault_key_commitment(&a).unwrap(),
            vault_key_commitment(&c).unwrap()
        );
    }

    #[test]
    fn recovery_key_format_is_bip39_mnemonic() {
        let key = format_recovery_key(&[0xFFu8; RECOVERY_KEY_BYTES]);
        let words: Vec<&str> = key.split_whitespace().collect();
        assert_eq!(words.len(), 24, "expected 24 BIP-39 words, got: {key}");
        assert!(bip39::Mnemonic::parse_in(bip39::Language::English, key.as_str()).is_ok());
    }

    #[test]
    fn recovery_key_format_differs_per_input() {
        let a = format_recovery_key(&[0x00u8; RECOVERY_KEY_BYTES]);
        let b = format_recovery_key(&[0xFFu8; RECOVERY_KEY_BYTES]);
        assert_ne!(a, b);
    }

    #[test]
    fn recovery_key_input_accepts_only_bip39_24_word_keys() {
        let phrase = format_recovery_key(&[0x00u8; RECOVERY_KEY_BYTES]);
        let noisy_phrase = phrase
            .split_whitespace()
            .map(str::to_ascii_uppercase)
            .collect::<Vec<_>>()
            .join("   ");
        assert_eq!(normalize_recovery_key_input(&noisy_phrase), Some(phrase));

        assert_eq!(
            normalize_recovery_key_input(" h5bf5-xg2y7-zrw32-yrc2d-ks3ke-09c84 "),
            None,
            "dash-delimited recovery codes are not accepted"
        );

        let custom_passphrase = " exact  custom  passphrase ";
        assert_eq!(
            normalize_recovery_key_input(custom_passphrase),
            None,
            "custom passphrases are not accepted"
        );

        let twelve_word_passphrase = "\
            ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\
        ";
        assert_eq!(
            normalize_recovery_key_input(twelve_word_passphrase),
            None,
            "shorter BIP-39 mnemonics are not accepted as recovery keys"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_hex() {
        let phrase = format_recovery_key(&[0x00u8; RECOVERY_KEY_BYTES]);
        let fp = fingerprint_recovery_key(&phrase);
        assert!(fp.starts_with("sha256:"));
        assert_eq!(fp.len(), "sha256:".len() + 64);
        assert!(
            fp.chars()
                .skip("sha256:".len())
                .all(|c| c.is_ascii_hexdigit())
        );
        let fp2 = fingerprint_recovery_key(
            &phrase
                .split_whitespace()
                .map(str::to_ascii_uppercase)
                .collect::<Vec<_>>()
                .join("   "),
        );
        assert_eq!(fp, fp2);
    }

    #[test]
    fn passkey_prf_wrapper_round_trips_recovery_key() {
        let phrase = format_recovery_key(&[0x11u8; RECOVERY_KEY_BYTES]);
        let prf = [0xA5u8; PASSKEY_PRF_OUTPUT_LEN];
        let salt = [0x5Au8; PASSKEY_WRAP_SALT_LEN];
        let aad = br#"{"account_id":"did:web:alice.example","wrap_id":"ck:recovery-wrap:test"}"#;

        let sealed = seal_recovery_key_with_passkey_prf(&phrase, &prf, &salt, aad).unwrap();
        assert_eq!(sealed.salt_b64, B64.encode(salt));
        assert!(sealed.ciphertext_digest.starts_with("sha256:"));

        let opened = open_recovery_key_with_passkey_prf(
            &prf,
            &sealed.salt_b64,
            &sealed.nonce_b64,
            &sealed.ciphertext_b64,
            aad,
        )
        .unwrap();
        assert_eq!(opened, phrase);
    }

    #[test]
    fn passkey_prf_wrapper_rejects_wrong_prf_or_aad() {
        let phrase = format_recovery_key(&[0x22u8; RECOVERY_KEY_BYTES]);
        let prf = [0x07u8; PASSKEY_PRF_OUTPUT_LEN];
        let salt = [0x08u8; PASSKEY_WRAP_SALT_LEN];
        let aad = b"stable-aad";
        let sealed = seal_recovery_key_with_passkey_prf(&phrase, &prf, &salt, aad).unwrap();

        let wrong_prf = [0x09u8; PASSKEY_PRF_OUTPUT_LEN];
        assert!(
            open_recovery_key_with_passkey_prf(
                &wrong_prf,
                &sealed.salt_b64,
                &sealed.nonce_b64,
                &sealed.ciphertext_b64,
                aad,
            )
            .is_err()
        );

        assert!(
            open_recovery_key_with_passkey_prf(
                &prf,
                &sealed.salt_b64,
                &sealed.nonce_b64,
                &sealed.ciphertext_b64,
                b"tampered-aad",
            )
            .is_err()
        );
    }

    #[test]
    fn passkey_prf_wrapper_rejects_non_recovery_key_input() {
        let prf = [0x33u8; PASSKEY_PRF_OUTPUT_LEN];
        let salt = [0x44u8; PASSKEY_WRAP_SALT_LEN];
        let err = seal_recovery_key_with_passkey_prf("custom passphrase", &prf, &salt, b"aad")
            .unwrap_err();
        assert!(err.to_string().contains("24-word recovery key"));
    }

    #[test]
    fn live_seal_open_path_works_with_random_salt() {
        // Smoke test for the "real" entry point that uses getrandom for the salt.
        let root = derive_vault_kek(b"random-salt-passphrase").unwrap();
        let ctx = test_ctx(b"{}");
        let sealed = seal_vault(&root, &ctx, b"hello").unwrap();
        let plain = open_vault(
            b"random-salt-passphrase",
            &ctx,
            &sealed.salt_b64,
            &sealed.nonce_b64,
            &sealed.nonce_salt_b64,
            &sealed.key_commitment,
            &sealed.ciphertext_b64,
        )
        .unwrap();
        assert_eq!(plain, b"hello");
    }
}
