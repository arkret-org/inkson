//! RFC 9180 HPKE base-mode seal/open for `recipient_method=recovery_public_key`
//! key backups.
//!
//! Spec: `identity/key-management.md` §7.5.2 — a backup DEK / payload is
//! public-key sealed to the actor's recovery public key. The recovery PUBLIC
//! key is published (recovery policy / DID Document `recoveryKeyAgreement`), so
//! ANY device can seal a backup to it without holding any secret; only the
//! recovery PRIVATE key (unlocked via the recovery policy — passphrase /
//! threshold / hardware) can open it. This is the spec's fresh-device restore
//! path: a brand-new browser unlocks the recovery private key and opens
//! `mls_history` without first holding the account secret (breaks the
//! "new device must already have a secret to read its own backups" circularity).
//!
//! Suite (NORMATIVE): this surface pins the v1 **default-MUST** application-layer
//! HPKE suite `ak.hpke_x25519_aead_chacha20poly1305.v1`
//! (`hpke-suite-registry.json`): standard RFC 9180 base mode —
//! KEM `DHKEM(X25519, HKDF-SHA256)`, KDF `HKDF-SHA256`, AEAD ChaCha20-Poly1305
//! (96-bit nonce). The AEAD nonce is the key-schedule-derived `base_nonce`
//! (single-shot seq=0) and is NOT carried on the wire.
//!
//! The seal/open crypto is delegated to
//! `arkret_crypto::secret_share::{seal_base_mode_to_x25519_pubkey,
//! open_base_mode_with_x25519_privkey}` (the SDK's RFC 9180 SetupBase, validated
//! byte-for-byte against the RFC 9180 CFRG KAT). This module keeps the
//! recovery-keypair derivation and re-frames the SDK's single
//! `base64url(enc || ct)` blob into the envelope's separate `enc` / `ciphertext`
//! fields ([`HpkeSealed`]). The former YGN-DRY-06 non-convergence no longer
//! holds: with both sides on standard RFC 9180 the constructions are identical.

use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Canonical wire scheme / `hpke_suite` selector for this surface: the v1
/// default-MUST application-layer HPKE suite. Emitted into the envelope so the
/// AEAD `name` (`chacha20_poly1305`) is unambiguously consistent with the
/// selected suite per `hpke-suite-registry.json` registry rules.
pub const HPKE_SUITE: &str = "ak.hpke_x25519_aead_chacha20poly1305.v1";

/// HKDF info domain separator for deriving the recovery X25519 keypair from
/// BIP-39 entropy (see [`derive_recovery_keypair_from_entropy`]). This is an
/// opaque, stable domain tag — its byte value MUST NOT change or existing
/// recovery keys would derive a different keypair.
const HPKE_KEY_SCHEDULE_INFO: &[u8] = b"arkret-recovery-public-key-hpke-x25519-chacha20poly1305-v1";

/// Output of [`hpke_seal`]: the RFC 9180 DHKEM encapsulated key (`enc`, the
/// 32-byte ephemeral X25519 public key) and the AEAD ciphertext (`ct+tag`, no
/// wire nonce — the AEAD nonce is the key-schedule-derived `base_nonce`). Both
/// travel base64url in the `recovery_public_key` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeSealed {
    /// DHKEM encapsulated ephemeral public key (32 bytes).
    pub enc: Vec<u8>,
    /// RFC 9180 AEAD ciphertext (Poly1305 tag appended); no wire nonce.
    pub ciphertext: Vec<u8>,
}

/// Coerce a raw key slice into a 32-byte X25519 scalar/point.
fn x25519_32(bytes: &[u8], label: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be 32 bytes, got {}", bytes.len()))
}

/// Generate a fresh X25519 recovery keypair. Returns `(private_key, public_key)`
/// as raw 32-byte values; the public key is published and the private key is
/// stored (encrypted) in the recovery vault.
pub fn generate_recovery_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|err| anyhow!("hpke keypair rng: {err}"))?;
    let secret = StaticSecret::from(seed);
    seed.zeroize();
    let public = X25519PublicKey::from(&secret);
    Ok((secret.to_bytes().to_vec(), public.as_bytes().to_vec()))
}

/// Deterministically derive the X25519 recovery keypair from the canonical
/// 24-word Recovery Key. This binds the HPKE private key to the offline
/// recovery credential instead of creating a second random secret.
pub fn derive_recovery_keypair_from_recovery_key(recovery_key: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let canonical = crate::recovery_crypto::normalize_recovery_key_input(recovery_key)
        .ok_or_else(|| anyhow!("recovery key must be a canonical 24-word BIP-39 mnemonic"))?;
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        &canonical, "", 0,
    )
    .map_err(|err| anyhow!("derive identity recovery key material: {err}"))?;
    Ok((
        key_material.backup_hpke_serialized_private_key.to_vec(),
        key_material.backup_hpke_public_key.to_vec(),
    ))
}

/// Deterministically derive the X25519 recovery keypair from BIP-39 entropy.
pub fn derive_recovery_keypair_from_entropy(entropy: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if entropy.len() != crate::recovery_crypto::RECOVERY_KEY_BYTES {
        return Err(anyhow!(
            "recovery key entropy must be {} bytes",
            crate::recovery_crypto::RECOVERY_KEY_BYTES
        ));
    }
    let mut ikm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, entropy)
        .expand(HPKE_KEY_SCHEDULE_INFO, ikm.as_mut_slice())
        .map_err(|_| anyhow!("hpke recovery key hkdf expand failed"))?;
    let secret = StaticSecret::from(*ikm);
    let public = X25519PublicKey::from(&secret);
    Ok((secret.to_bytes().to_vec(), public.as_bytes().to_vec()))
}

/// RFC 9180 base-mode seal `plaintext` to `recipient_public_key`, delegating to
/// the SDK's SetupBase implementation. `info` and `aad` are bound exactly as the
/// receiver must reproduce them (§7.5.2: `info` = canonical_json of the envelope
/// identity tuple; `aad` = the envelope AEAD AAD). The SDK returns one
/// `base64url(enc || ct)` blob; we split it into the envelope's `enc` /
/// `ciphertext` fields.
pub fn hpke_seal(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed> {
    // Validate the key length up front for a clearer error than the SDK's.
    let _ = x25519_32(recipient_public_key, "recovery HPKE public key")?;
    let blob_b64 = arkret_crypto::secret_share::seal_base_mode_to_x25519_pubkey(
        recipient_public_key,
        plaintext,
        info,
        aad,
    )
    .map_err(|err| anyhow!("hpke seal: {err}"))?;
    let blob = URL_SAFE_NO_PAD
        .decode(blob_b64.as_bytes())
        .map_err(|err| anyhow!("hpke seal blob decode: {err}"))?;
    if blob.len() <= 32 {
        return Err(anyhow!("hpke seal blob too short for enc + ciphertext"));
    }
    Ok(HpkeSealed {
        enc: blob[..32].to_vec(),
        ciphertext: blob[32..].to_vec(),
    })
}

/// RFC 9180 base-mode open: recover the plaintext with the recovery private key,
/// delegating to the SDK's SetupBaseR. Re-frames the envelope's separate `enc` /
/// `ciphertext` fields into the SDK's `base64url(enc || ct)` blob. Fails (wrong
/// key / tampered ciphertext / mismatched info or aad) → `Err`.
pub fn hpke_open(
    recipient_private_key: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let _ = x25519_32(enc, "hpke enc (encapsulated key)")?;
    let mut blob = Vec::with_capacity(enc.len() + ciphertext.len());
    blob.extend_from_slice(enc);
    blob.extend_from_slice(ciphertext);
    let blob_b64 = URL_SAFE_NO_PAD.encode(&blob);
    arkret_crypto::secret_share::open_base_mode_with_x25519_privkey(
        recipient_private_key,
        &blob_b64,
        info,
        aad,
    )
    .map_err(|err| anyhow!("hpke open: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let (sk, pk) = generate_recovery_keypair().unwrap();
        let info = b"info-transcript";
        let aad = b"aead-aad";
        let pt = b"the account MLS secret payload";
        let sealed = hpke_seal(&pk, info, aad, pt).unwrap();
        let opened = hpke_open(&sk, &sealed.enc, info, aad, &sealed.ciphertext).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn open_rejects_wrong_private_key() {
        let (_sk, pk) = generate_recovery_keypair().unwrap();
        let (other_sk, _other_pk) = generate_recovery_keypair().unwrap();
        let sealed = hpke_seal(&pk, b"info", b"aad", b"secret").unwrap();
        assert!(hpke_open(&other_sk, &sealed.enc, b"info", b"aad", &sealed.ciphertext).is_err());
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let (sk, pk) = generate_recovery_keypair().unwrap();
        let mut sealed = hpke_seal(&pk, b"info", b"aad", b"secret").unwrap();
        // Flip the first ciphertext byte so we hit the AEAD tag check.
        if let Some(byte) = sealed.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }
        assert!(hpke_open(&sk, &sealed.enc, b"info", b"aad", &sealed.ciphertext).is_err());
    }

    #[test]
    fn open_rejects_mismatched_info_or_aad() {
        let (sk, pk) = generate_recovery_keypair().unwrap();
        let sealed = hpke_seal(&pk, b"info-A", b"aad-A", b"secret").unwrap();
        // Wrong info.
        assert!(hpke_open(&sk, &sealed.enc, b"info-B", b"aad-A", &sealed.ciphertext).is_err());
        // Wrong aad.
        assert!(hpke_open(&sk, &sealed.enc, b"info-A", b"aad-B", &sealed.ciphertext).is_err());
    }

    #[test]
    fn distinct_keypairs_each_round_trip() {
        // Two independently-generated keypairs are distinct and don't cross-open.
        let (sk1, pk1) = generate_recovery_keypair().unwrap();
        let (sk2, pk2) = generate_recovery_keypair().unwrap();
        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
        let s1 = hpke_seal(&pk1, b"i", b"a", b"m1").unwrap();
        assert_eq!(
            hpke_open(&sk1, &s1.enc, b"i", b"a", &s1.ciphertext).unwrap(),
            b"m1"
        );
        assert!(hpke_open(&sk2, &s1.enc, b"i", b"a", &s1.ciphertext).is_err());
    }

    #[test]
    fn recovery_key_derives_stable_hpke_keypair() {
        let mnemonic = crate::recovery_crypto::format_recovery_key(&[7u8; 32]);
        let first = derive_recovery_keypair_from_recovery_key(&mnemonic).unwrap();
        let second = derive_recovery_keypair_from_recovery_key(&mnemonic).unwrap();
        assert_eq!(first, second);
        let identity_material =
            arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
                &mnemonic, "", 0,
            )
            .unwrap();
        assert_eq!(
            first.0,
            identity_material.backup_hpke_serialized_private_key
        );
        assert_eq!(first.1, identity_material.backup_hpke_public_key);

        let other = derive_recovery_keypair_from_recovery_key(
            &crate::recovery_crypto::format_recovery_key(&[8u8; 32]),
        )
        .unwrap();
        assert_ne!(first, other);
    }

    #[test]
    fn derived_recovery_keypair_round_trips_hpke() {
        let mnemonic = crate::recovery_crypto::format_recovery_key(&[9u8; 32]);
        let (sk, pk) = derive_recovery_keypair_from_recovery_key(&mnemonic).unwrap();
        let sealed = hpke_seal(&pk, b"info", b"aad", b"secret").unwrap();
        let opened = hpke_open(&sk, &sealed.enc, b"info", b"aad", &sealed.ciphertext).unwrap();
        assert_eq!(opened, b"secret");
    }
}
