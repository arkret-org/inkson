//! HPKE (RFC 9180) base-mode seal/open for `recipient_method=recovery_public_key`
//! key backups.
//!
//! Spec: `identity/key-management.md` §7.5.2 — a backup DEK / payload is HPKE
//! base-mode encrypted to the actor's recovery public key. The recovery PUBLIC
//! key is published (recovery policy / DID Document `recoveryKeyAgreement`), so
//! ANY device can seal a backup to it without holding any secret; only the
//! recovery PRIVATE key (unlocked via the recovery policy — passphrase /
//! threshold / hardware) can open it. This is the spec's fresh-device restore
//! path: a brand-new browser unlocks the recovery private key and HPKE-opens
//! `mls_history` without first holding the account secret (breaks the
//! "new device must already have a secret to read its own backups" circularity).
//!
//! Suite (NORMATIVE per §7.5.2): KEM `DHKEM(X25519, HKDF-SHA256)`, KDF
//! `HKDF-SHA256`, AEAD `ChaCha20Poly1305`, Mode `Base`. We use the audited
//! `hpke-rs` crate with the RustCrypto backend (wasm-friendly) so the wire bytes
//! are RFC 9180 conformant for cross-implementation interop.

use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use sha2::Sha256;

/// Output of [`hpke_seal`]: the KEM encapsulated key (`enc`) and the AEAD
/// ciphertext. Both travel on the wire (base64url) in the
/// `recovery_public_key` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeSealed {
    /// KEM output / encapsulated ephemeral public key.
    pub enc: Vec<u8>,
    /// AEAD ciphertext (tag appended).
    pub ciphertext: Vec<u8>,
}

fn suite() -> Hpke<HpkeRustCrypto> {
    Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

const RECOVERY_KEY_HPKE_INFO: &[u8] = b"cokret-recovery-key-hpke-x25519-v1";

/// Generate a fresh X25519 recovery keypair. Returns `(private_key, public_key)`
/// as raw bytes; the public key is published and the private key is stored
/// (encrypted) in the recovery vault.
pub fn generate_recovery_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let hpke = suite();
    let mut ikm = [0u8; 32];
    getrandom::fill(&mut ikm).map_err(|err| anyhow!("hpke keypair rng: {err}"))?;
    let keypair = hpke
        .derive_key_pair(&ikm)
        .map_err(|err| anyhow!("hpke derive key pair: {err:?}"))?;
    let (sk, pk) = keypair.into_keys();
    Ok((sk.as_slice().to_vec(), pk.as_slice().to_vec()))
}

/// Deterministically derive the X25519 recovery keypair from the canonical
/// 24-word Recovery Key. This binds the HPKE private key to the offline
/// recovery credential instead of creating a second random secret.
pub fn derive_recovery_keypair_from_recovery_key(recovery_key: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let canonical = crate::recovery_crypto::normalize_recovery_key_input(recovery_key)
        .ok_or_else(|| anyhow!("recovery key must be a canonical 24-word BIP-39 mnemonic"))?;
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, canonical.as_str())
        .map_err(|err| anyhow!("recovery key mnemonic: {err}"))?;
    derive_recovery_keypair_from_entropy(&mnemonic.to_entropy())
}

/// Deterministically derive the X25519 recovery keypair from BIP-39 entropy.
pub fn derive_recovery_keypair_from_entropy(entropy: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if entropy.len() != crate::recovery_crypto::RECOVERY_KEY_BYTES {
        return Err(anyhow!(
            "recovery key entropy must be {} bytes",
            crate::recovery_crypto::RECOVERY_KEY_BYTES
        ));
    }
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(None, entropy)
        .expand(RECOVERY_KEY_HPKE_INFO, &mut ikm)
        .map_err(|_| anyhow!("hpke recovery key hkdf expand failed"))?;
    let keypair = suite()
        .derive_key_pair(&ikm)
        .map_err(|err| anyhow!("hpke derive key pair: {err:?}"))?;
    let (sk, pk) = keypair.into_keys();
    Ok((sk.as_slice().to_vec(), pk.as_slice().to_vec()))
}

/// HPKE base-mode seal `plaintext` to `recipient_public_key`. `info` and `aad`
/// are bound into the HPKE context exactly as the receiver must reproduce them
/// (§7.5.2: `info` = canonical_json of the envelope identity tuple; `aad` = the
/// envelope AEAD AAD).
pub fn hpke_seal(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed> {
    let mut hpke = suite();
    let pk = HpkePublicKey::new(recipient_public_key.to_vec());
    let (enc, ciphertext) = hpke
        .seal(&pk, info, aad, plaintext, None, None, None)
        .map_err(|err| anyhow!("hpke seal: {err:?}"))?;
    Ok(HpkeSealed { enc, ciphertext })
}

/// HPKE base-mode open: recover the plaintext with the recovery private key.
/// Fails (wrong key / tampered ciphertext / mismatched info or aad) → `Err`.
pub fn hpke_open(
    recipient_private_key: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let hpke = suite();
    let sk = HpkePrivateKey::new(recipient_private_key.to_vec());
    hpke.open(enc, &sk, info, aad, ciphertext, None, None, None)
        .map_err(|err| anyhow!("hpke open: {err:?}"))
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
        if let Some(byte) = sealed.ciphertext.first_mut() {
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
