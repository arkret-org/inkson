//! Hybrid Logical Clock (HLC) per arkret-spec section 6.4 — thin wrapper
//! over the HLC helpers re-exported by `arkret_sdk`.
//!
//! Format: `<physical_hex_12>-<logical_hex_4>-<node_hex_8>`
//! - 48-bit millisecond timestamp (12 hex chars)
//! - 16-bit logical counter (4 hex chars)
//! - 32-bit node hash (8 hex chars)
//!
//! HLC validation responsibilities are delegated to the SDK:
//! - format validation / parsing: `validate_hlc_format` / `parse_hlc`,
//! - encode + overflow semantics: `arkret_sdk::Hlc::new`.
//!
//! New timestamps are minted by `crate::signing_stamp` through Garth's
//! durable Realm-scoped allocator. This type only parses and formats values
//! already present in local projections.

use std::fmt;

use arkret_sdk::{Hlc as SdkHlc, parse_hlc, validate_hlc_format};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A Hybrid Logical Clock timestamp.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hlc {
    /// 48-bit millisecond physical timestamp.
    pub physical_ms: u64,
    /// 32-bit logical counter for same-millisecond events.
    pub logical: u32,
    /// 32-bit node identifier hash.
    pub node_id: u32,
}

impl Serialize for Hlc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = self.try_encode().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Self::parse(&encoded).map_err(serde::de::Error::custom)
    }
}

impl Hlc {
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

    /// Encode to the hex string format.
    ///
    /// Format and overflow semantics are delegated to the SDK's `Hlc` newtype
    /// via [`Self::try_encode`]: the candidate string is validated by
    /// `arkret_sdk::Hlc::new`, which rejects out-of-range components (e.g. a
    /// logical counter that does not fit the 4-hex field) instead of silently
    /// truncating it.
    ///
    /// For strict wire validation, use [`Self::try_encode`]. This infallible
    /// helper is used by display paths and never truncates oversized
    /// components; an invalid hand-built value will render as an invalid
    /// candidate string rather than panic.
    pub fn encode(&self) -> String {
        format!(
            "{:012x}-{:04x}-{:08x}",
            self.physical_ms, self.logical, self.node_id
        )
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

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HlcError {
    /// The string is not a valid canonical v1 HLC. Format validation is
    /// delegated to the SDK (`validate_hlc_format` / `arkret_sdk::Hlc::new`),
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
    fn serde_uses_the_canonical_wire_string() {
        let hlc = Hlc::from_parts(0x0001_8ef0_1234, 0x0005, 0xdead_beef);
        let json = serde_json::to_string(&hlc).unwrap();
        assert_eq!(json, "\"00018ef01234-0005-deadbeef\"");
        assert_eq!(serde_json::from_str::<Hlc>(&json).unwrap(), hlc);
        assert!(serde_json::from_str::<Hlc>(r#"{"physical_ms": 1}"#).is_err());
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
}
