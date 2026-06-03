//! Hybrid Logical Clock (HLC) per cokret-spec section 6.4.
//!
//! Format: `<physical_hex_12>-<logical_hex_4>-<node_hex_8>`
//! - 48-bit millisecond timestamp (12 hex chars)
//! - 16-bit logical counter (4 hex chars)
//! - 32-bit node hash (8 hex chars; SHA-256 prefix, see [`hash_node_id`])
//!
//! The node-id derivation MUST stay byte-compatible with the SDK's
//! `cokret_sdk::hlc::HlcGenerator::compute_node_id` (SHA-256 of the node
//! identifier string, big-endian first 4 bytes encoded as 8 lowercase
//! hex chars). The cross-impl test `hash_node_id_matches_sdk_compute_node_id`
//! at the bottom of this file pins both implementations against each
//! other; if it ever drifts, downstream HLCs become wire-incompatible
//! with anything the SDK produced from the same DID.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use cokret_sdk::Hlc as SdkHlc;
use cokret_sdk::hlc::{HlcGenerator, parse_hlc, validate_hlc_format};
use serde::{Deserialize, Serialize};

/// A Hybrid Logical Clock timestamp.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hlc {
    /// 48-bit millisecond physical timestamp.
    pub physical_ms: u64,
    /// 32-bit logical counter for same-millisecond events.
    pub logical: u32,
    /// 32-bit node identifier hash.
    pub node_id: u32,
}

impl Hlc {
    /// Create a new HLC with the current wall-clock time.
    ///
    /// Delegates to the SDK's `HlcGenerator`, which owns the canonical
    /// wall-clock source and node-id derivation. We mint a generator for
    /// `node_id`, read its current HLC and decode it back into this struct's
    /// three fields. This keeps the physical-time source and node-id hashing
    /// byte-identical to anything the SDK produces for the same DID, instead
    /// of yougen reading the clock and hashing the node id on its own.
    pub fn now(node_id: &str) -> Self {
        let hlc = HlcGenerator::new(node_id).current();
        let parts = parse_hlc(hlc.as_str())
            .expect("HlcGenerator emits a spec-valid HLC string parseable by parse_hlc");
        Self {
            physical_ms: parts.physical_ms,
            logical: parts.logical,
            node_id: u32::from_str_radix(&parts.node_id, 16)
                .expect("SDK node-id segment is 8 lowercase hex chars"),
        }
    }

    /// Create an HLC from components.
    pub fn from_parts(physical_ms: u64, logical: u32, node_id: u32) -> Self {
        Self {
            physical_ms,
            logical,
            node_id,
        }
    }

    /// Parse an HLC from its canonical string format.
    ///
    /// Format validation is delegated to the SDK's `validate_hlc_format` /
    /// `parse_hlc`, which enforce the strict v1 wire form
    /// (`^[0-9a-f]{12}-[0-9a-f]{4}-[0-9a-f]{8}$` — lowercase hex, fixed
    /// widths). This replaces yougen's hand-rolled length checks, so a string
    /// that is upper-case or wrong-width is rejected here exactly as the SDK
    /// would reject it on the wire.
    pub fn parse(s: &str) -> Result<Self, HlcError> {
        validate_hlc_format(s).map_err(|_| HlcError::InvalidFormat(s.to_owned()))?;
        let parts = parse_hlc(s).map_err(|_| HlcError::InvalidFormat(s.to_owned()))?;
        let node_id = u32::from_str_radix(&parts.node_id, 16)
            .map_err(|_| HlcError::InvalidNode(parts.node_id.clone()))?;
        Ok(Self {
            physical_ms: parts.physical_ms,
            logical: parts.logical,
            node_id,
        })
    }

    /// Encode to canonical hex string format.
    ///
    /// Format and overflow semantics are delegated to the SDK's `Hlc` newtype
    /// via [`Self::try_encode`]: the candidate string is validated by
    /// `cokret_sdk::Hlc::new`, which rejects out-of-range components (e.g. a
    /// logical counter that does not fit the 4-hex field) instead of silently
    /// truncating it the way yougen's old hand-rolled `format!` did.
    ///
    /// Every `Hlc` minted through [`Self::now`] / [`Self::from_parts`] /
    /// [`Self::parse`] in this crate carries spec-valid components, so this
    /// path does not panic on any value yougen actually produces. The panic
    /// guards a programmer error (hand-built out-of-spec components) rather
    /// than masking it with a truncated wire value.
    pub fn encode(&self) -> String {
        self.try_encode()
            .expect("Hlc components fit the canonical v1 wire format")
    }

    /// Fallible encode: returns the canonical hex string, or an error if the
    /// components do not fit the SDK's strict v1 wire format (e.g. a logical
    /// counter wider than 4 hex digits). This is the SDK's overflow behaviour,
    /// replacing yougen's old silent `logical.min(0xffff)` truncation.
    pub fn try_encode(&self) -> Result<String, HlcError> {
        let candidate = format!(
            "{:012x}-{:04x}-{:08x}",
            self.physical_ms, self.logical, self.node_id
        );
        let hlc = SdkHlc::new(candidate).map_err(|_| {
            HlcError::InvalidFormat(format!(
                "{:012x}-{:04x}-{:08x}",
                self.physical_ms, self.logical, self.node_id
            ))
        })?;
        Ok(hlc.into_string())
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

/// Hash a node identifier string to the 32-bit value used by [`Hlc`]'s
/// `node_id` segment.
///
/// Delegates to the SDK's `HlcGenerator`, which owns the canonical node-id
/// derivation (SHA-256(`node_id`), first 4 bytes as 8 lowercase hex chars).
/// We mint a generator for `node_id`, read its current HLC and parse out the
/// node segment, then decode the 8 hex chars back to the `u32` this struct
/// stores. This removes yougen's duplicate SHA-256 prefix implementation
/// while staying byte-compatible with anything the SDK produced for the same
/// DID (pinned by `hash_node_id_matches_sdk_compute_node_id`).
pub fn hash_node_id(node_id: &str) -> u32 {
    let hlc = HlcGenerator::new(node_id).current();
    let parts = parse_hlc(hlc.as_str())
        .expect("HlcGenerator emits a spec-valid HLC string parseable by parse_hlc");
    u32::from_str_radix(&parts.node_id, 16).expect("SDK node-id segment is 8 lowercase hex chars")
}

/// A global monotonic sequence counter for operation ordering.
static GLOBAL_SEQ: AtomicU64 = AtomicU64::new(0);

/// Generate the next monotonic sequence number.
pub fn next_seq() -> u64 {
    let wall_floor = Utc::now()
        .timestamp_millis()
        .max(0)
        .try_into()
        .unwrap_or(0_u64)
        .saturating_mul(1000);
    loop {
        let current = GLOBAL_SEQ.load(Ordering::Relaxed);
        let next = wall_floor.max(current.saturating_add(1));
        if GLOBAL_SEQ
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return next;
        }
    }
}

/// Advance the local sequence floor after observing remote history.
pub fn observe_seq(seq: u64) {
    let floor = seq.saturating_add(1);
    let _ = GLOBAL_SEQ.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (floor > current).then_some(floor)
    });
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HlcError {
    /// The string is not a valid canonical v1 HLC. Format validation is
    /// delegated to the SDK (`validate_hlc_format` / `cokret_sdk::Hlc::new`),
    /// which enforces the strict `^[0-9a-f]{12}-[0-9a-f]{4}-[0-9a-f]{8}$` form;
    /// this variant carries the offending input.
    #[error("invalid HLC format: {0}")]
    InvalidFormat(String),
    /// The node segment is well-formed hex per the SDK but does not fit the
    /// `u32` this struct stores.
    #[error("invalid node component: {0}")]
    InvalidNode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encode_parse() {
        let hlc = Hlc::from_parts(0x0001_8ef0_1234, 0x0000_0005, 0xdead_beef);
        let encoded = hlc.encode();
        assert_eq!(encoded.len(), 26); // 12 + 1 + 4 + 1 + 8
        let parsed = Hlc::parse(&encoded).unwrap();
        assert_eq!(hlc, parsed);
    }

    #[test]
    fn display_matches_encode() {
        let hlc = Hlc::from_parts(1000, 0, 42);
        assert_eq!(hlc.to_string(), hlc.encode());
    }

    #[test]
    fn encode_rejects_logical_overflow_instead_of_truncating() {
        // The old hand-rolled `encode` did `logical.min(0xffff)`, silently
        // truncating any logical counter that overflowed the 4-hex field.
        // The SDK-backed encoder reports the overflow instead.
        let overflowing = Hlc::from_parts(0x0001_8ef0_1234, 0x0001_0000, 0xdead_beef);
        assert!(
            overflowing.try_encode().is_err(),
            "logical counter wider than 4 hex digits must not encode"
        );

        // A logical counter that fits still round-trips.
        let ok = Hlc::from_parts(0x0001_8ef0_1234, 0x0000_ffff, 0xdead_beef);
        assert!(ok.try_encode().is_ok());
        assert_eq!(Hlc::parse(&ok.encode()).unwrap(), ok);
    }

    #[test]
    fn parse_rejects_invalid_format() {
        assert!(Hlc::parse("not-an-hlc").is_err());
        assert!(Hlc::parse("000000000001-00000002").is_err());
        assert!(Hlc::parse("000000000001-00000002-deadbeef").is_err());
    }

    #[test]
    fn hash_node_id_is_deterministic() {
        assert_eq!(hash_node_id("device_1"), hash_node_id("device_1"));
        assert_ne!(hash_node_id("device_1"), hash_node_id("device_2"));
    }

    /// Pin yougen's `hash_node_id` to the same byte output as the SDK's
    /// `HlcGenerator::compute_node_id`. The SDK's helper produces the
    /// 8-hex-char node segment by SHA-256(input)[..4] formatted as
    /// `{:02x}{:02x}{:02x}{:02x}`. Encoding our `u32` as `{:08x}` must
    /// produce the same 8 chars; otherwise HLCs minted by yougen and
    /// the SDK for the same DID disagree on the node segment.
    #[test]
    fn hash_node_id_matches_sdk_compute_node_id() {
        use sha2::{Digest, Sha256};
        for input in [
            "did:web:alice.example.com",
            "did:web:bob.example.com",
            "yougen",
            "",
            "01970e589d21-0001-a13f9c2e",
        ] {
            let digest = Sha256::digest(input.as_bytes());
            let sdk_node: String = digest[0..4].iter().map(|b| format!("{:02x}", b)).collect();
            let yougen_node = format!("{:08x}", hash_node_id(input));
            assert_eq!(
                yougen_node, sdk_node,
                "node-id encoding diverged from SDK for {input:?}",
            );
        }
    }

    #[test]
    fn next_seq_is_monotonic() {
        let a = next_seq();
        let b = next_seq();
        assert!(b > a);
    }

    #[test]
    fn observe_seq_advances_next_sequence_floor() {
        observe_seq(9_000_000_000_000_000);
        assert!(next_seq() > 9_000_000_000_000_000);
    }
}
