//! Canonical `did:key` (Ed25519) multibase encoding shared across yougen.
//!
//! Previously this logic lived in `move_builder` and was *copied* into
//! `local_state` to keep `local_state` independent of `move_builder`'s
//! heavier dependency graph. Both copies (and the `cross_signing` caller)
//! now share this dependency-light module so the encoding lives in exactly
//! one place.
//!
//! Encoding: `z<base58btc(0xed 0x01 || pubkey32)>` — the multibase form
//! that `did:key` DID URLs and DID Document `verificationMethod` entries
//! use for Ed25519 keys.

use ed25519_dalek::VerifyingKey;

/// Encode an Ed25519 public key as the multibase fragment used by
/// `did:key` DID URLs and DID Document `verificationMethod` entries:
/// `z<base58btc(0xed 0x01 || pubkey32)>`.
pub fn encode_ed25519_did_key_multibase(verifying_key: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(verifying_key.as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

/// Compose a full `did:key` DID URL from a verifying key
/// (`did:key:z<...>`).
pub fn did_key_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    format!("did:key:{}", encode_ed25519_did_key_multibase(verifying_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn did_key_round_trips_prefix() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let mb = encode_ed25519_did_key_multibase(&vk);
        assert!(mb.starts_with('z'));
        assert_eq!(did_key_from_verifying_key(&vk), format!("did:key:{mb}"));
    }
}
