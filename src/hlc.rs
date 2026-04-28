//! Hybrid Logical Clock (HLC) per contrix-spec section 6.4.
//!
//! Format: `<physical_hex_12>-<logical_hex_8>-<node_hex_8>`
//! - 48-bit millisecond timestamp (12 hex chars)
//! - 32-bit logical counter (8 hex chars)
//! - 32-bit node hash (8 hex chars)

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
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
            "{:012x}-{:08x}-{:08x}",
            self.physical_ms, self.logical, self.node_id
        )
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

/// Hash a node ID string to a 32-bit value (FNV-1a).
pub fn hash_node_id(node_id: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in node_id.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// A global monotonic sequence counter for operation ordering.
static GLOBAL_SEQ: AtomicU64 = AtomicU64::new(1);

/// Generate the next monotonic sequence number.
pub fn next_seq() -> u64 {
    GLOBAL_SEQ.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HlcError {
    InvalidFormat(String),
    InvalidPhysical(String),
    InvalidPhysicalLength(usize),
    InvalidLogical(String),
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
        assert_eq!(encoded.len(), 30); // 12 + 1 + 8 + 1 + 8
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
    }

    #[test]
    fn hash_node_id_is_deterministic() {
        assert_eq!(hash_node_id("device_1"), hash_node_id("device_1"));
        assert_ne!(hash_node_id("device_1"), hash_node_id("device_2"));
    }

    #[test]
    fn next_seq_is_monotonic() {
        let a = next_seq();
        let b = next_seq();
        assert!(b > a);
    }
}
