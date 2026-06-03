//! Canonical JSON wrapper used by yougen write paths.
//!
//! Re-exports `contrix_sdk::canonical` so all envelope, Move, Anchor, and key-
//! backup bodies can be hashed and signed against a single canonical encoder
//! instead of relying on `serde_json`'s default object-key order.

pub use contrix_sdk::canonical::{
    canonical_json_bytes as sdk_canonical_json_bytes,
    canonical_json_string as sdk_canonical_json_string, canonical_sha256 as sdk_canonical_sha256,
    sha256_digest as sdk_sha256_digest, validate_timestamp_canonical,
};
use serde::Serialize;

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

// F-CANONICAL-1 (2026-05-19): named entry points for the three
// wire-shaped canonicalizations that yougen actually emits / verifies.
// The SDK already enforces field ordering / integer-only numbers /
// UTF-8 byte order through `sdk_canonical_json_bytes`; these wrappers
// make the call-site intent explicit (so an audit reader sees
// "signing the move canonical bytes" instead of an ambiguous
// "canonical_json_bytes(&move)") and give us a single throat to choke
// when the spec adds new canonicalization rules for a specific
// envelope type.

/// F-CANONICAL-1: canonical bytes for an [`EventEnvelope`] payload —
/// the input the signer hashes when producing the detached JWS over
/// an inbound event. Matches `conformance/encoding.md §2` (event
/// envelope canonicalization rules: sorted keys, integer-only
/// numbers, no whitespace).
pub fn canonical_event_envelope_bytes(
    envelope: &crate::operation::EventEnvelope,
) -> anyhow::Result<Vec<u8>> {
    canonical_json_bytes(envelope)
}

/// F-CANONICAL-1: canonical bytes for a Move body. Used at the move
/// signer / verifier seam. Generic so callers can pass either the
/// SDK's typed `Move` (when available in scope) or a `serde_json::Value`
/// representing one. The encoder is the same — yougen does not maintain
/// a parallel Move serializer.
pub fn canonical_move_bytes<T: Serialize>(move_payload: &T) -> anyhow::Result<Vec<u8>> {
    canonical_json_bytes(move_payload)
}

/// F-CANONICAL-1: canonical bytes for an [`crate::anchor_witness::AnchorWitnessChain`].
/// The witness verifier passes this byte string into the per-witness
/// signature check so a signature produced against a non-canonical
/// serialization can't replay across anchors. See
/// `sync/finality-and-consensus.md §3`.
pub fn canonical_anchor_witness_bytes(
    chain: &crate::anchor_witness::AnchorWitnessChain,
) -> anyhow::Result<Vec<u8>> {
    canonical_json_bytes(chain)
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
        let body = json!({"flow_id": "ck:flow:abc", "title": "Ops"});
        let d = canonical_event_digest(&body).unwrap();
        assert!(d.starts_with("sha256:"));
        assert_eq!(d, canonical_sha256(&body).unwrap());
    }

    #[test]
    fn timestamp_validation_pass_through() {
        assert!(validate_timestamp_canonical("2026-05-14T00:00:00Z").is_ok());
        assert!(validate_timestamp_canonical("2026-05-14T00:00:00+00:00").is_err());
    }

    // ── F-CANONICAL-1 ────────────────────────────────────────────────

    #[test]
    fn canonical_move_bytes_normalizes_key_order() {
        // Two semantically identical move payloads with different
        // serialization orders MUST produce the same canonical bytes,
        // otherwise downstream signatures diverge.
        let a = json!({"flow_id": "ck:flow:1", "patch": {"title": "x"}});
        let b = json!({"patch": {"title": "x"}, "flow_id": "ck:flow:1"});
        assert_eq!(
            canonical_move_bytes(&a).unwrap(),
            canonical_move_bytes(&b).unwrap()
        );
    }

    #[test]
    fn canonical_anchor_witness_bytes_round_trip_is_deterministic() {
        use crate::anchor_witness::{AnchorWitness, AnchorWitnessChain};
        let chain = AnchorWitnessChain {
            anchor_id: "ck:anchor:1".to_owned(),
            post_state_root: "sha256:root".to_owned(),
            witnesses: vec![AnchorWitness {
                signer_did: "did:web:alice".to_owned(),
                signer_domain: "alice.example".to_owned(),
                signature: "sig".to_owned(),
                signed_at: None,
            }],
            threshold_required: 1,
        };
        let a = canonical_anchor_witness_bytes(&chain).unwrap();
        let b = canonical_anchor_witness_bytes(&chain).unwrap();
        assert_eq!(a, b);
    }
}
