//! DHKEM(X25519, HKDF-SHA256) + XChaCha20-Poly1305 base-mode seal/open for
//! `recipient_method=recovery_public_key` key backups.
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
//! HPKE suite `ck.hpke_x25519_aead_xchacha20poly1305.v1`
//! (`hpke-suite-registry.json`): KEM `DHKEM(X25519, HKDF-SHA256)`, KDF
//! `HKDF-SHA256`, AEAD **XChaCha20-Poly1305** (extended 192-bit nonce). The
//! AEAD is outside RFC 9180's base AEAD registry, so this is a hand-rolled
//! DHKEM + HKDF + XChaCha20 construction (the same crypto stack the SDK uses in
//! `secret_share::seal_history_secret_to_device_pubkey`), NOT the `hpke-rs`
//! RFC 9180 single-shot API — which only offers the 96-bit-nonce ChaCha20
//! variant and would force the non-default `ck.hpke_x25519_aead_chacha20poly1305.v1`
//! interop suite, breaking the omitted-`hpke_suite`-selector default and
//! producing an `aead.name` that contradicts the default-MUST row.
//!
//! Wire shape ([`HpkeSealed`]): `enc` = the 32-byte ephemeral X25519 public key
//! (the KEM encapsulation); `ciphertext` = `nonce(24) || AEAD ciphertext+tag`.
//! Both travel base64url in the `recovery_public_key` envelope. The caller's
//! `info` transcript is bound into the HKDF context and `aad` into the AEAD AAD,
//! exactly as the opener reconstructs them.
//!
//! NOT delegated to `cokret_sdk::secret_share::{seal_base_mode_to_x25519_pubkey,
//! open_base_mode_with_x25519_privkey}` (YGN-DRY-06 verdict): the two
//! constructions are deliberately NOT byte-isomorphic, and already-sealed
//! backups pin this one —
//! 1. Nonce: this surface uses a fresh random 24-byte XNonce carried on the
//!    wire (`nonce || ct`); the SDK base-mode entry uses a fixed zero nonce
//!    (single-use key) and carries no nonce.
//! 2. Wire framing: this surface keeps `enc` and `ciphertext` as two separate
//!    envelope fields; the SDK returns one `base64url(ephemeral_pub || ct)`
//!    blob.
//! 3. HKDF info: this surface expands with
//!    `HPKE_KEY_SCHEDULE_INFO || 0x00 || caller_info`; the SDK expands with
//!    the caller `info` bytes verbatim (transformable, but moot given 1–2).
//! Switching would make every existing `recovery_public_key`-sealed backup
//! unopenable. If convergence is ever wanted it needs a versioned envelope
//! migration, not a drop-in swap.

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Canonical wire scheme / `hpke_suite` selector for this surface: the v1
/// default-MUST application-layer HPKE suite. Emitted into the envelope so the
/// AEAD `name` (`xchacha20_poly1305`) is unambiguously consistent with the
/// selected suite per `hpke-suite-registry.json` registry rules.
pub const HPKE_SUITE: &str = "ck.hpke_x25519_aead_xchacha20poly1305.v1";

/// HKDF info domain separator for the DHKEM key schedule of this surface.
const HPKE_KEY_SCHEDULE_INFO: &[u8] = b"cokret-recovery-public-key-hpke-x25519-xchacha20-v1";

/// XChaCha20-Poly1305 nonce length (extended 192-bit nonce).
const XNONCE_LEN: usize = 24;

/// Output of [`hpke_seal`]: the KEM encapsulated key (`enc`, the 32-byte
/// ephemeral X25519 public key) and the AEAD ciphertext (`nonce || ct+tag`).
/// Both travel on the wire (base64url) in the `recovery_public_key` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeSealed {
    /// KEM output / encapsulated ephemeral public key (32 bytes).
    pub enc: Vec<u8>,
    /// `nonce(24) || AEAD ciphertext (tag appended)`.
    pub ciphertext: Vec<u8>,
}

/// Coerce a raw key slice into a 32-byte X25519 scalar/point.
fn x25519_32(bytes: &[u8], label: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be 32 bytes, got {}", bytes.len()))
}

/// Derive the per-message XChaCha20-Poly1305 key from the DH shared secret,
/// binding the encapsulated key, recipient public key and the caller's `info`
/// transcript into the HKDF salt/info so the opener reproduces it byte-for-byte.
fn derive_aead_key(
    shared_secret: &[u8],
    enc: &[u8; 32],
    recipient_pub: &[u8; 32],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = Vec::with_capacity(enc.len() + recipient_pub.len());
    salt.extend_from_slice(enc);
    salt.extend_from_slice(recipient_pub);
    let mut hkdf_info = Vec::with_capacity(HPKE_KEY_SCHEDULE_INFO.len() + 1 + info.len());
    hkdf_info.extend_from_slice(HPKE_KEY_SCHEDULE_INFO);
    hkdf_info.push(0);
    hkdf_info.extend_from_slice(info);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&hkdf_info, key.as_mut_slice())
        .map_err(|_| anyhow!("hpke aead key hkdf expand failed"))?;
    Ok(key)
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
    let mut ikm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, entropy)
        .expand(HPKE_KEY_SCHEDULE_INFO, ikm.as_mut_slice())
        .map_err(|_| anyhow!("hpke recovery key hkdf expand failed"))?;
    let secret = StaticSecret::from(*ikm);
    let public = X25519PublicKey::from(&secret);
    Ok((secret.to_bytes().to_vec(), public.as_bytes().to_vec()))
}

/// DHKEM(X25519) + XChaCha20-Poly1305 base-mode seal `plaintext` to
/// `recipient_public_key`. `info` and `aad` are bound into the context exactly
/// as the receiver must reproduce them (§7.5.2: `info` = canonical_json of the
/// envelope identity tuple; `aad` = the envelope AEAD AAD).
pub fn hpke_seal(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed> {
    let recipient_pub = x25519_32(recipient_public_key, "recovery HPKE public key")?;
    let recipient_public = X25519PublicKey::from(recipient_pub);

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|err| anyhow!("hpke ephemeral rng: {err}"))?;
    let ephemeral = StaticSecret::from(seed);
    seed.zeroize();
    let enc = *X25519PublicKey::from(&ephemeral).as_bytes();

    let shared = ephemeral.diffie_hellman(&recipient_public);
    if shared.as_bytes().iter().all(|b| *b == 0) {
        return Err(anyhow!("hpke x25519 shared secret must not be all zero"));
    }
    let key = derive_aead_key(shared.as_bytes(), &enc, &recipient_pub, info)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| anyhow!("hpke invalid aead key"))?;
    let mut nonce = [0u8; XNONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|err| anyhow!("hpke nonce rng: {err}"))?;
    let aead_ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("hpke aead seal failed"))?;

    let mut ciphertext = Vec::with_capacity(XNONCE_LEN + aead_ct.len());
    ciphertext.extend_from_slice(&nonce);
    ciphertext.extend_from_slice(&aead_ct);
    Ok(HpkeSealed {
        enc: enc.to_vec(),
        ciphertext,
    })
}

/// DHKEM(X25519) + XChaCha20-Poly1305 base-mode open: recover the plaintext
/// with the recovery private key. Fails (wrong key / tampered ciphertext /
/// mismatched info or aad) → `Err`.
pub fn hpke_open(
    recipient_private_key: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut privkey = Zeroizing::new(x25519_32(
        recipient_private_key,
        "recovery HPKE private key",
    )?);
    let enc_arr = x25519_32(enc, "hpke enc (encapsulated key)")?;
    if ciphertext.len() < XNONCE_LEN {
        return Err(anyhow!("hpke ciphertext shorter than nonce"));
    }

    // SEC-06: build the StaticSecret from the wrapped copy, then drop the raw
    // array via Zeroizing (StaticSecret itself zeroizes on drop).
    let recipient_secret = StaticSecret::from(*privkey);
    privkey.zeroize();
    let recipient_pub = *X25519PublicKey::from(&recipient_secret).as_bytes();
    let ephemeral_public = X25519PublicKey::from(enc_arr);
    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    if shared.as_bytes().iter().all(|b| *b == 0) {
        return Err(anyhow!("hpke x25519 shared secret must not be all zero"));
    }
    let key = derive_aead_key(shared.as_bytes(), &enc_arr, &recipient_pub, info)?;

    let (nonce, aead_ct) = ciphertext.split_at(XNONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| anyhow!("hpke invalid aead key"))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: aead_ct, aad })
        .map_err(|_| anyhow!("hpke aead open failed"))
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
        // Tamper a byte past the 24-byte nonce so we hit the AEAD tag check.
        if let Some(byte) = sealed.ciphertext.get_mut(XNONCE_LEN) {
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
