//! Canonical `did:key` (Ed25519) helpers shared across inkson.

use ed25519_dalek::VerifyingKey;

/// Encode an Ed25519 public key as the multibase fragment used by
/// `did:key` DID URLs and DID Document `verificationMethod` entries:
/// `z<base58btc(0xed 0x01 || pubkey32)>`.
pub fn encode_ed25519_did_key_multibase(verifying_key: &VerifyingKey) -> String {
    arkret_sdk::ed25519_pubkey_to_did_key_multibase(verifying_key.as_bytes())
}

/// Encode an X25519 public key as the multibase form used for device
/// `hpke_key` records (`z<base58btc(0xec 0x01 || pubkey32)>`,
/// multicodec x25519-pub).
pub fn encode_x25519_multibase(public_key: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(2 + public_key.len());
    bytes.extend_from_slice(&[0xec, 0x01]);
    bytes.extend_from_slice(public_key);
    arkret_sdk::encode_multibase_base58btc(bytes)
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
