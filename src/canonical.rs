//! Canonical JSON wrapper used by yougen write paths.
//!
//! Re-exports `contrix_sdk::canonical` so all envelope, Move, Anchor, and key-
//! backup bodies can be hashed and signed against a single canonical encoder
//! instead of relying on `serde_json`'s default object-key order.

use serde::Serialize;

pub use contrix_sdk::canonical::{
    canonical_json_bytes as sdk_canonical_json_bytes,
    canonical_json_string as sdk_canonical_json_string,
    canonical_sha256 as sdk_canonical_sha256, sha256_digest as sdk_sha256_digest,
    validate_timestamp_canonical,
};

/// Wire-canonical JSON bytes — sorted object keys, integer-only numbers per
/// `encoding.md` §3.2. Returns an `anyhow::Error` so call sites can chain into
/// the rest of yougen's error surface without dragging `contrix_core::Error`
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

/// Helper: digest of a canonical operation/event body for proof binding.
///
/// Equivalent to `canonical_sha256(body)`, but kept as a named entry point so
/// call sites are self-documenting at the point of signing.
pub fn canonical_event_digest<T: Serialize>(body: &T) -> anyhow::Result<String> {
    canonical_sha256(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn canonical_event_digest_round_trip() {
        let body = json!({"flow_id": "cx:flow:abc", "title": "Ops"});
        let d = canonical_event_digest(&body).unwrap();
        assert!(d.starts_with("sha256:"));
        assert_eq!(d, canonical_sha256(&body).unwrap());
    }

    #[test]
    fn timestamp_validation_pass_through() {
        assert!(validate_timestamp_canonical("2026-05-14T00:00:00Z").is_ok());
        assert!(validate_timestamp_canonical("2026-05-14T00:00:00+00:00").is_err());
    }
}
