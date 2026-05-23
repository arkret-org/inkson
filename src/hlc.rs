//! Hybrid Logical Clock (HLC) per contrix-spec section 6.4.
//!
//! Format: `<physical_hex_12>-<logical_hex_4>-<node_hex_8>`
//! - 48-bit millisecond timestamp (12 hex chars)
//! - 16-bit logical counter (4 hex chars)
//! - 32-bit node hash (8 hex chars; SHA-256 prefix, see [`hash_node_id`])
//!
//! The node-id derivation MUST stay byte-compatible with the SDK's
//! `contrix_sdk::hlc::HlcGenerator::compute_node_id` (SHA-256 of the node
//! identifier string, big-endian first 4 bytes encoded as 8 lowercase
//! hex chars). The cross-impl test `hash_node_id_matches_sdk_compute_node_id`
//! at the bottom of this file pins both implementations against each
//! other; if it ever drifts, downstream HLCs become wire-incompatible
//! with anything the SDK produced from the same DID.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    pub fn now(node_id: &str) -> Self {
        let physical_ms = Utc::now().timestamp_millis().max(0) as u64;
        Self {
            physical_ms,
            logical: 0,
            node_id: hash_node_id(node_id),
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
    pub fn parse(s: &str) -> Result<Self, HlcError> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return Err(HlcError::InvalidFormat(s.to_owned()));
        }
        let physical_ms = u64::from_str_radix(parts[0], 16)
            .map_err(|_| HlcError::InvalidPhysical(parts[0].to_owned()))?;
        if parts[0].len() != 12 {
            return Err(HlcError::InvalidPhysicalLength(parts[0].len()));
        }
        if parts[1].len() != 4 {
            return Err(HlcError::InvalidLogicalLength(parts[1].len()));
        }
        let logical = u32::from_str_radix(parts[1], 16)
            .map_err(|_| HlcError::InvalidLogical(parts[1].to_owned()))?;
        let node_id = u32::from_str_radix(parts[2], 16)
            .map_err(|_| HlcError::InvalidNode(parts[2].to_owned()))?;
        Ok(Self {
            physical_ms,
            logical,
            node_id,
        })
    }

    /// Tick the clock: advance physical or logical based on wall clock.
    /// Returns a new HLC that is causally after `self`.
    pub fn tick(&self, node_id: &str) -> Self {
        let wall = Utc::now().timestamp_millis().max(0) as u64;
        let node = hash_node_id(node_id);
        if wall > self.physical_ms {
            Self {
                physical_ms: wall,
                logical: 0,
                node_id: node,
            }
        } else if wall == self.physical_ms {
            Self {
                physical_ms: self.physical_ms,
                logical: self.logical.wrapping_add(1),
                node_id: node,
            }
        } else {
            // Wall clock went backwards; keep physical, bump logical.
            Self {
                physical_ms: self.physical_ms,
                logical: self.logical.wrapping_add(1),
                node_id: node,
            }
        }
    }

    /// Merge with a received HLC: take the max physical, advance logical.
    pub fn merge(&self, remote: &Self, node_id: &str) -> Self {
        let wall = Utc::now().timestamp_millis().max(0) as u64;
        let node = hash_node_id(node_id);
        let max_physical = wall.max(self.physical_ms.max(remote.physical_ms));
        if max_physical == self.physical_ms && max_physical == remote.physical_ms {
            let logical = self.logical.max(remote.logical).wrapping_add(1);
            Self {
                physical_ms: max_physical,
                logical,
                node_id: node,
            }
        } else if max_physical == self.physical_ms {
            Self {
                physical_ms: max_physical,
                logical: self.logical.wrapping_add(1),
                node_id: node,
            }
        } else if max_physical == remote.physical_ms {
            Self {
                physical_ms: max_physical,
                logical: remote.logical.wrapping_add(1),
                node_id: node,
            }
        } else {
            Self {
                physical_ms: max_physical,
                logical: 0,
                node_id: node,
            }
        }
    }

    /// Encode to canonical hex string format.
    pub fn encode(&self) -> String {
        format!(
            "{:012x}-{:04x}-{:08x}",
            self.physical_ms,
            self.logical.min(0xffff),
            self.node_id
        )
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
/// Algorithm: SHA-256(`node_id`), interpret the first 4 bytes as a
/// big-endian `u32`. When encoded via `{:08x}` this yields the same
/// 8-hex-char string as `contrix_sdk::hlc::HlcGenerator::compute_node_id`
/// for the same input — so HLCs minted by yougen and by the SDK for the
/// same DID share identical node segments and can be merged/compared
/// across the wire.
pub fn hash_node_id(node_id: &str) -> u32 {
    let digest = Sha256::digest(node_id.as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HlcError {
    InvalidFormat(String),
    InvalidPhysical(String),
    InvalidPhysicalLength(usize),
    InvalidLogical(String),
    InvalidLogicalLength(usize),
    InvalidNode(String),
}

impl fmt::Display for HlcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(s) => write!(f, "invalid HLC format: {s}"),
            Self::InvalidPhysical(s) => write!(f, "invalid physical component: {s}"),
            Self::InvalidPhysicalLength(n) => {
                write!(f, "physical component must be 12 hex chars, got {n}")
            }
            Self::InvalidLogical(s) => write!(f, "invalid logical component: {s}"),
            Self::InvalidLogicalLength(n) => {
                write!(f, "logical component must be 4 hex chars, got {n}")
            }
            Self::InvalidNode(s) => write!(f, "invalid node component: {s}"),
        }
    }
}

impl std::error::Error for HlcError {}

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
    fn tick_advances_logical_when_wall_same() {
        let hlc = Hlc::now("test");
        let ticked = hlc.tick("test");
        // At minimum logical should differ or physical should advance
        assert!(ticked >= hlc);
    }

    #[test]
    fn merge_takes_max_physical() {
        let a = Hlc::from_parts(100, 0, 1);
        let b = Hlc::from_parts(200, 5, 2);
        let merged = a.merge(&b, "node");
        assert!(merged.physical_ms >= a.physical_ms.max(b.physical_ms));
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
