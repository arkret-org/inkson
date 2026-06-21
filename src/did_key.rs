//! Canonical `did:key` (Ed25519) helpers shared across yougen.

use ed25519_dalek::VerifyingKey;

/// Encode an Ed25519 public key as the multibase fragment used by
/// `did:key` DID URLs and DID Document `verificationMethod` entries:
/// `z<base58btc(0xed 0x01 || pubkey32)>`.
pub fn encode_ed25519_did_key_multibase(verifying_key: &VerifyingKey) -> String {
    cokret_sdk::ed25519_pubkey_to_did_key_multibase(verifying_key.as_bytes())
}

/// Compose a full `did:key` DID URL from a verifying key
/// (`did:key:z<...>`).
pub fn did_key_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    format!(
        "did:key:{}",
        encode_ed25519_did_key_multibase(verifying_key)
    )
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn did_key_round_trips_prefix() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let mb = encode_ed25519_did_key_multibase(&vk);
        assert!(mb.starts_with('z'));
        assert_eq!(did_key_from_verifying_key(&vk), format!("did:key:{mb}"));
    }
}
