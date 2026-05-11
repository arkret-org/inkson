//! Structured cursor encoding per contrix-spec section 6.5.
//!
//! Cursors are structured JSON with Base64URL transport:
//! - version, timestamp, space positions (frontier + HLC + state hash),
//!   device positions, expiration.

use crate::hlc::Hlc;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

/// A structured sync cursor per contrix-spec.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cursor {
    /// Cursor format version (currently 1).
    pub version: u32,
    /// ISO 8601 timestamp when cursor was created.
    pub timestamp: String,
    /// Per-space position information.
    #[serde(default)]
    pub spaces: std::collections::BTreeMap<String, SpacePosition>,
    /// Per-device position information.
    #[serde(default)]
    pub devices: std::collections::BTreeMap<String, DevicePosition>,
    /// Optional cursor expiration time (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Position within a specific space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpacePosition {
    /// The event or anchor frontier IDs this position covers.
    #[serde(default)]
    pub frontier: Vec<String>,
    /// HLC timestamp at this position.
    pub hlc: String,
    /// State hash at this position.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_hash: Option<String>,
}

/// Position for a specific device.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DevicePosition {
    /// Last acknowledged sequence number.
    pub seq: u64,
    /// HLC timestamp of last ack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<String>,
}

impl Cursor {
    /// Create a new cursor with current timestamp.
    pub fn new() -> Self {
        Self {
            version: 1,
            timestamp: chrono::Utc::now().to_rfc3339(),
            spaces: std::collections::BTreeMap::new(),
            devices: std::collections::BTreeMap::new(),
            expires_at: None,
        }
    }

    /// Set a space position in this cursor.
    pub fn with_space(mut self, space_id: impl Into<String>, pos: SpacePosition) -> Self {
        self.spaces.insert(space_id.into(), pos);
        self
    }

    /// Set a device position in this cursor.
    pub fn with_device(mut self, device_id: impl Into<String>, pos: DevicePosition) -> Self {
        self.devices.insert(device_id.into(), pos);
        self
    }

    /// Set cursor expiration.
    pub fn with_expires_at(mut self, expires_at: impl Into<String>) -> Self {
        self.expires_at = Some(expires_at.into());
        self
    }

    /// Encode cursor to Base64URL string for transport.
    pub fn encode(&self) -> anyhow::Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(URL_SAFE_NO_PAD.encode(&json))
    }

    /// Decode cursor from Base64URL transport string.
    pub fn decode(encoded: &str) -> anyhow::Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Check if this cursor has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(ref expires) = self.expires_at {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                return chrono::Utc::now() > exp.with_timezone(&chrono::Utc);
            }
        }
        false
    }

    /// Get the HLC for a specific space, if available.
    pub fn space_hlc(&self, space_id: &str) -> Option<Hlc> {
        self.spaces
            .get(space_id)
            .and_then(|pos| Hlc::parse(&pos.hlc).ok())
    }

    /// Get a simple string representation (the next_batch token from server).
    /// Falls back to encoded cursor if no server token is available.
    pub fn as_batch_token(&self) -> anyhow::Result<String> {
        self.encode()
    }
}

impl Default for Cursor {
    fn default() -> Self {
        Self::new()
    }
}

impl SpacePosition {
    pub fn new(hlc: impl Into<String>) -> Self {
        Self {
            frontier: Vec::new(),
            hlc: hlc.into(),
            state_hash: None,
        }
    }

    pub fn with_frontier(mut self, frontier: Vec<String>) -> Self {
        self.frontier = frontier;
        self
    }

    pub fn with_state_hash(mut self, hash: impl Into<String>) -> Self {
        self.state_hash = Some(hash.into());
        self
    }
}

impl DevicePosition {
    pub fn new(seq: u64) -> Self {
        Self { seq, hlc: None }
    }

    pub fn with_hlc(mut self, hlc: impl Into<String>) -> Self {
        self.hlc = Some(hlc.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_encode_decode_round_trip() {
        let cursor = Cursor::new()
            .with_space(
                "cx:space:test",
                SpacePosition::new("0018ef01234a-00000005-deadbeef")
                    .with_frontier(vec!["cx:event:frontier-1".into()])
                    .with_state_hash("abc123"),
            )
            .with_device(
                "device_1",
                DevicePosition::new(42).with_hlc("0018ef01234a-00000003-11111111"),
            );

        let encoded = cursor.encode().unwrap();
        let decoded = Cursor::decode(&encoded).unwrap();
        assert_eq!(cursor, decoded);
    }

    #[test]
    fn cursor_is_not_expired_when_no_expiration() {
        let cursor = Cursor::new();
        assert!(!cursor.is_expired());
    }

    #[test]
    fn cursor_space_hlc_extraction() {
        let cursor = Cursor::new().with_space(
            "cx:space:test",
            SpacePosition::new("0018ef01234a-00000005-deadbeef"),
        );
        let hlc = cursor.space_hlc("cx:space:test").unwrap();
        assert_eq!(hlc.physical_ms, 0x0018ef01234a);
        assert_eq!(hlc.logical, 5);
    }

    #[test]
    fn base64url_transport_is_url_safe() {
        let cursor = Cursor::new().with_space(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            SpacePosition::new("0018ef01234a-00000001-aaaaaaaa"),
        );
        let encoded = cursor.encode().unwrap();
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }
}
