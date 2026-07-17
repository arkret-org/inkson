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

/// Helper: digest of a canonical operation/event body for proof binding.
///
/// Equivalent to `canonical_sha256(body)`, but kept as a named entry point so
/// call sites are self-documenting at the point of signing.
pub fn canonical_event_digest<T: Serialize>(body: &T) -> anyhow::Result<String> {
    canonical_sha256(body)
}

// F-CANONICAL-1 (2026-05-19): named entry points for the three
// wire-shaped canonicalizations that inkson actually emits / verifies.
// The SDK already enforces field ordering / integer-only numbers /
// UTF-8 byte order through `sdk_canonical_json_bytes`; these wrappers
// make the call-site intent explicit (so an audit reader sees
// "signing the move canonical bytes" instead of an ambiguous
// "canonical_json_bytes(&move)") and give us a single throat to choke
// when the spec adds new canonicalization rules for a specific
// envelope type.

/// F-CANONICAL-1: canonical bytes for a SDK [`arkret_sdk::Event`] payload —
/// the input the signer hashes when producing the detached JWS over
/// an inbound event. Matches `conformance/encoding.md §2` (event
/// envelope canonicalization rules: sorted keys, integer-only
/// numbers, no whitespace) and excludes `proofs` / `unsigned` exactly
/// as [`arkret_sdk::Event::event_digest`] does.
pub fn canonical_event_envelope_bytes(envelope: &arkret_sdk::Event) -> anyhow::Result<Vec<u8>> {
    canonical_json_bytes(&envelope.digest_payload()?)
}

/// F-CANONICAL-1: canonical bytes for a Move body. Used at the move
/// signer / verifier seam. Generic so callers can pass either the
/// SDK's typed `Move` (when available in scope) or a `serde_json::Value`
/// representing one. The encoder is the same — inkson does not maintain
/// a parallel Move serializer.
pub fn canonical_move_bytes<T: Serialize>(move_payload: &T) -> anyhow::Result<Vec<u8>> {
    canonical_json_bytes(move_payload)
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
    fn canonical_event_digest_round_trip() {
        let body = json!({"strand_id": "ak:strand:abc", "title": "Ops"});
        let d = canonical_event_digest(&body).unwrap();
        assert!(d.starts_with("sha256:"));
        assert_eq!(d, canonical_sha256(&body).unwrap());
    }

    #[test]
    fn timestamp_validation_pass_through() {
        assert!(validate_timestamp_canonical("2026-05-14T00:00:00Z").is_ok());
        assert!(validate_timestamp_canonical("2026-05-14T00:00:00+00:00").is_err());
    }

    #[test]
    fn hex_decode_round_trips_and_rejects_invalid_input() {
        assert_eq!(hex_decode("00ffA5").unwrap(), vec![0x00, 0xff, 0xa5]);
        assert_eq!(hex_encode(&hex_decode("deadbeef").unwrap()), "deadbeef");
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    // ── F-CANONICAL-1 ────────────────────────────────────────────────

    #[test]
    fn canonical_move_bytes_normalizes_key_order() {
        // Two semantically identical move payloads with different
        // serialization orders MUST produce the same canonical bytes,
        // otherwise downstream signatures diverge.
        let a = json!({"strand_id": "ak:strand:1", "patch": {"title": "x"}});
        let b = json!({"patch": {"title": "x"}, "strand_id": "ak:strand:1"});
        assert_eq!(
            canonical_move_bytes(&a).unwrap(),
            canonical_move_bytes(&b).unwrap()
        );
    }

    #[test]
    fn canonical_event_envelope_bytes_use_sdk_digest_payload() {
        let event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {"kind": "ak.content.text", "body": "hi"},
            "unsigned": {"local_only": true},
            "proofs": []
        }))
        .unwrap();

        let bytes = canonical_event_envelope_bytes(&event).unwrap();
        let as_text = std::str::from_utf8(&bytes).unwrap();

        assert_eq!(
            bytes,
            sdk_canonical_json_bytes(&event.digest_payload().unwrap()).unwrap()
        );
        assert!(!as_text.contains("proofs"));
        assert!(!as_text.contains("unsigned"));
    }
}
