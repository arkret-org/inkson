//! Canonical JSON wrapper used by inkson write paths.
//!
//! Re-exports `arkret_sdk::canonical` so all envelope, Move, Seal, and key-
//! backup bodies can be hashed and signed against a single canonical encoder
//! instead of relying on `serde_json`'s default object-key order.

pub use arkret_sdk::canonical::{
    canonical_json_bytes as sdk_canonical_json_bytes,
    canonical_json_string as sdk_canonical_json_string, canonical_sha256 as sdk_canonical_sha256,
    sha256_digest as sdk_sha256_digest, sha256_hex as sdk_sha256_hex, validate_timestamp_canonical,
};
use serde::Serialize;

/// Wire-canonical JSON bytes — sorted object keys, integer-only numbers per
/// `encoding.md` §3.2. Returns an `anyhow::Error` so call sites can chain into
/// the rest of inkson's error surface without dragging `arkret_sdk::Error`
/// across module boundaries.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    sdk_canonical_json_bytes(value).map_err(|e| anyhow::anyhow!("canonical encode failed: {e:?}"))
}

pub fn canonical_json_string<T: Serialize>(value: &T) -> anyhow::Result<String> {
    sdk_canonical_json_string(value).map_err(|e| anyhow::anyhow!("canonical encode failed: {e:?}"))
}

/// `sha256:<hex>` digest over the canonical bytes of `value`.
pub fn canonical_sha256<T: Serialize>(value: &T) -> anyhow::Result<String> {
    sdk_canonical_sha256(value).map_err(|e| anyhow::anyhow!("canonical hash failed: {e:?}"))
}

/// `sha256:<hex>` digest over `bytes` directly. Useful for hashing canonical
/// bytes that have already been built by another path (e.g. SDK Move
/// canonicalization).
pub fn sha256_digest(bytes: impl AsRef<[u8]>) -> String {
    sdk_sha256_digest(bytes)
}

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    sdk_sha256_hex(bytes.as_ref())
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
    fn key_order_does_not_affect_digest() {
        let a = json!({"b": 2, "a": 1, "c": {"y": 1, "x": 2}});
        let b = json!({"c": {"x": 2, "y": 1}, "a": 1, "b": 2});
        assert_eq!(canonical_sha256(&a).unwrap(), canonical_sha256(&b).unwrap());
    }

    #[test]
    fn canonical_string_is_sorted() {
        let value = json!({"z": 1, "a": 2});
        assert_eq!(canonical_json_string(&value).unwrap(), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn float_numbers_rejected() {
        let value = json!({"n": 1.5});
        assert!(canonical_json_string(&value).is_err());
    }

    #[test]
    fn timestamp_validation_pass_through() {
        assert!(validate_timestamp_canonical("2026-05-14T00:00:00.000Z").is_ok());
        assert!(validate_timestamp_canonical("2026-05-14T00:00:00+00:00").is_err());
    }

    #[test]
    fn hex_decode_round_trips_and_rejects_invalid_input() {
        assert_eq!(hex_decode("00ffA5").unwrap(), vec![0x00, 0xff, 0xa5]);
        assert_eq!(hex_encode(&hex_decode("deadbeef").unwrap()), "deadbeef");
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }
}
