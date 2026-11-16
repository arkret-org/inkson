//! Canonical JSON wrapper used by inkson write paths.
//!
//! Adapts `arkret_sdk::canonical` so Event and key-backup bodies can be hashed and signed against a
//! single canonical encoder instead of relying on `serde_json`'s default object-key order.

pub use arkret_sdk::canonical::validate_timestamp_canonical;
use serde::Serialize;

/// Wire-canonical JSON bytes — sorted object keys, integer-only numbers per
/// `encoding.md` §3.2. Returns an `anyhow::Error` so call sites can chain into
/// the rest of inkson's error surface without dragging `arkret_sdk::Error`
/// across module boundaries.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    arkret_sdk::canonical::canonical_json_bytes(value)
        .map_err(|e| anyhow::anyhow!("canonical encode failed: {e:?}"))
}

pub fn canonical_json_string<T: Serialize>(value: &T) -> anyhow::Result<String> {
    arkret_sdk::canonical::canonical_json_string(value)
        .map_err(|e| anyhow::anyhow!("canonical encode failed: {e:?}"))
}

/// `sha256:<hex>` digest over the canonical bytes of `value`.
pub fn canonical_sha256<T: Serialize>(value: &T) -> anyhow::Result<String> {
    arkret_sdk::canonical::canonical_sha256(value)
        .map_err(|e| anyhow::anyhow!("canonical hash failed: {e:?}"))
}

/// `sha256:<hex>` digest over `bytes` directly. Useful for hashing canonical
/// bytes that have already been built by another path.
pub fn sha256_digest(bytes: impl AsRef<[u8]>) -> String {
    arkret_sdk::canonical::sha256_digest(bytes)
}

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    arkret_sdk::canonical::sha256_hex(bytes.as_ref())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    hex::decode(value).ok()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn float_numbers_rejected() {
        let value = json!({"n": 1.5});
        assert!(
            canonical_json_string(&value)
                .unwrap_err()
                .to_string()
                .starts_with("canonical encode failed:")
        );
        assert!(
            canonical_json_bytes(&value)
                .unwrap_err()
                .to_string()
                .starts_with("canonical encode failed:")
        );
        assert!(
            canonical_sha256(&value)
                .unwrap_err()
                .to_string()
                .starts_with("canonical hash failed:")
        );
    }
}
