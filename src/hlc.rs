//! Hybrid Logical Clock (HLC) per cokret-spec section 6.4 — thin wrapper
//! over `cokret_sdk::hlc`.
//!
//! Format: `<physical_hex_12>-<logical_hex_4>-<node_hex_8>`
//! - 48-bit millisecond timestamp (12 hex chars)
//! - 16-bit logical counter (4 hex chars)
//! - 32-bit node hash (8 hex chars)
//!
//! All HLC kernel responsibilities are delegated to the SDK:
//! - format validation / parsing: `validate_hlc_format` / `parse_hlc`,
//! - encode + overflow semantics: `cokret_sdk::Hlc::new`,
//! - node-id derivation: `HlcGenerator::compute_node_id` (`encoding.md` §7,
//!   `SHA256("cokret-hlc-v1" || realm_id || device_id || secret)[0:4]`),
//!   reached through generator construction because the helper is private.
//!
//! The only local responsibility left is injecting the physical clock
//! through `crate::clock`: the SDK generator's advancing entry points
//! (`generate` / `generate_with_remote` / `HlcGenerator::new`) read
//! `std::time::SystemTime::now()`, which panics on wasm32-unknown-unknown,
//! so this wrapper mints values via the clock-free constructor
//! `HlcGenerator::with_initial_time` + `current()`.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Build an SDK generator pinned to the given physical time.
///
/// Node-id derivation is the SDK's `compute_node_id` (`encoding.md` §7); it
/// is private, so generator construction is the supported way to run it.
/// yougen carries a single process-wide node identifier, which maps onto the
/// `device_id` slot with empty realm/secret — full §7 Realm-scoped secret
/// wiring is a separate work item; the node segment stays an opaque,
/// SDK-derived pseudonymous hash either way.
fn sdk_generator_at(node_id: &str, physical_ms: u64) -> HlcGenerator {
    HlcGenerator::with_initial_time("", node_id, &[], physical_ms)
}

impl Hlc {
    /// Create a new HLC with the current wall-clock time.
    ///
    /// Minting is delegated to the SDK generator; the clock is read through
    /// `crate::clock` (and injected via `with_initial_time`) so the wasm
    /// build never touches `std::time::SystemTime::now()`.
    pub fn now(node_id: &str) -> Self {
        let minted = sdk_generator_at(node_id, crate::clock::now_unix_ms().min(0xffffffffffff))
            .current();
        let parts =
            parse_hlc(minted.as_str()).expect("SDK-minted HLC string is parseable by parse_hlc");
        Self {
            physical_ms: parts.physical_ms,
            logical: parts.logical,
            node_id: u32::from_str_radix(&parts.node_id, 16)
                .expect("node-id segment is 8 lowercase hex chars"),
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
    /// widths), so a string that is upper-case or wrong-width is rejected
    /// here exactly as the SDK would reject it on the wire.
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
    /// truncating it.
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
    /// counter wider than 4 hex digits). This is the SDK's overflow
    /// behaviour — no silent truncation.
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

/// A global monotonic sequence counter for operation ordering.
static GLOBAL_SEQ: AtomicU64 = AtomicU64::new(0);

/// Generate the next monotonic sequence number.
pub fn next_seq() -> u64 {
    let wall_floor = crate::clock::now_unix_ms().saturating_mul(1000);
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
        // The SDK-backed encoder reports a logical counter that overflows
        // the 4-hex field instead of silently truncating it.
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
    fn now_node_segment_is_deterministic_per_identifier() {
        // The node segment comes from the SDK's `compute_node_id` derivation
        // (via generator construction): stable for the same identifier,
        // distinct across identifiers.
        let a1 = Hlc::now("device_1");
        let a2 = Hlc::now("device_1");
        let b = Hlc::now("device_2");
        assert_eq!(a1.node_id, a2.node_id);
        assert_ne!(a1.node_id, b.node_id);
    }

    #[test]
    fn now_round_trips_through_sdk_wire_format() {
        let hlc = Hlc::now("device_1");
        let encoded = hlc.encode();
        assert!(validate_hlc_format(&encoded).is_ok());
        assert_eq!(Hlc::parse(&encoded).unwrap(), hlc);
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
