//! Canonical JSON wrapper used by yougen write paths.
//!
//! Re-exports `cokret_sdk::canonical` so all envelope, Move, Seal, and key-
//! backup bodies can be hashed and signed against a single canonical encoder
//! instead of relying on `serde_json`'s default object-key order.

pub use cokret_sdk::canonical::{
    canonical_json_bytes as sdk_canonical_json_bytes,
    canonical_json_string as sdk_canonical_json_string, canonical_sha256 as sdk_canonical_sha256,
    sha256_digest as sdk_sha256_digest, sha256_hex as sdk_sha256_hex, validate_timestamp_canonical,
};
use serde::Serialize;

/// Wire-canonical JSON bytes — sorted object keys, integer-only numbers per
/// `encoding.md` §3.2. Returns an `anyhow::Error` so call sites can chain into
/// the rest of yougen's error surface without dragging `cokret_core::Error`
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

/// YOU-05-007: the crate's single lowercase-hex encoder — fixed width per
/// byte, no separator, matching the SDK's `canonical::sha256_digest` hex
/// tail style. Previously copied verbatim in `cross_signing`,
/// `crypto_boundary` and `mls::persistence`.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Helper: digest of a canonical operation/event body for proof binding.
///
/// Equivalent to `canonical_sha256(body)`, but kept as a named entry point so
/// call sites are self-documenting at the point of signing.
pub fn canonical_event_digest<T: Serialize>(body: &T) -> anyhow::Result<String> {
    canonical_sha256(body)
}

// F-CANONICAL-1 (2026-05-19): named entry points for the three
// wire-shaped canonicalizations that yougen actually emits / verifies.
// The SDK already enforces field ordering / integer-only numbers /
// UTF-8 byte order through `sdk_canonical_json_bytes`; these wrappers
// make the call-site intent explicit (so an audit reader sees
// "signing the move canonical bytes" instead of an ambiguous
// "canonical_json_bytes(&move)") and give us a single throat to choke
// when the spec adds new canonicalization rules for a specific
// envelope type.

/// F-CANONICAL-1: canonical bytes for a SDK [`cokret_sdk::Event`] payload —
/// the input the signer hashes when producing the detached JWS over
/// an inbound event. Matches `conformance/encoding.md §2` (event
/// envelope canonicalization rules: sorted keys, integer-only
/// numbers, no whitespace) and excludes `proofs` / `unsigned` exactly
/// as [`cokret_sdk::Event::event_digest`] does.
pub fn canonical_event_envelope_bytes(envelope: &cokret_sdk::Event) -> anyhow::Result<Vec<u8>> {
    canonical_json_bytes(&envelope.digest_payload()?)
}

/// F-CANONICAL-1: canonical bytes for a Move body. Used at the move
/// signer / verifier seam. Generic so callers can pass either the
/// SDK's typed `Move` (when available in scope) or a `serde_json::Value`
/// representing one. The encoder is the same — yougen does not maintain
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
        let body = json!({"strand_id": "ck:strand:abc", "title": "Ops"});
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
        let a = json!({"strand_id": "ck:strand:1", "patch": {"title": "x"}});
        let b = json!({"patch": {"title": "x"}, "strand_id": "ck:strand:1"});
        assert_eq!(
            canonical_move_bytes(&a).unwrap(),
            canonical_move_bytes(&b).unwrap()
        );
    }

    #[test]
    fn canonical_event_envelope_bytes_use_sdk_digest_payload() {
        let event: cokret_sdk::Event = serde_json::from_value(json!({
            "event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "kind": "ck.message.create",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {"kind": "ck.content.text", "body": "hi"},
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
