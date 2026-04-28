//! Conformance profiles, JSON schema validation, and security checks
//! per contrix-spec sections 12–13.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Conformance profile declarations per contrix-spec section 13.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceProfile {
    pub profile_id: String,
    pub version: String,
    pub description: String,
    pub supported: bool,
}

/// All known conformance profiles.
pub fn known_profiles() -> Vec<ConformanceProfile> {
    vec![
        ConformanceProfile {
            profile_id: "cx.profile.minimal_client.v1".into(),
            version: "1.0".into(),
            description: "Minimal client: basic sync, plaintext messaging, directory lookup".into(),
            supported: true,
        },
        ConformanceProfile {
            profile_id: "cx.profile.full_client.v1".into(),
            version: "1.0".into(),
            description: "Full client: all views, entity/relation management, capability checks"
                .into(),
            supported: false,
        },
        ConformanceProfile {
            profile_id: "cx.profile.e2ee_client.v1".into(),
            version: "1.0".into(),
            description: "E2EE client: MLS encryption, device management, key lifecycle".into(),
            supported: false,
        },
        ConformanceProfile {
            profile_id: "cx.profile.enterprise_client.v1".into(),
            version: "1.0".into(),
            description: "Enterprise client: capability delegation, audit, compliance".into(),
            supported: false,
        },
    ]
}

/// Plaintext boundary check per contrix-spec section 12.1.
/// Verifies that non-E2EE private content does not reach undelegated services.
pub struct PlaintextBoundary {
    /// Services that may receive plaintext.
    pub allowed_services: Vec<String>,
    /// Whether the current space is E2EE.
    pub is_e2ee: bool,
}

impl PlaintextBoundary {
    /// Check if sending plaintext to a service is allowed.
    pub fn can_send_plaintext(&self, service_did: &str) -> bool {
        if self.is_e2ee {
            // E2EE spaces: plaintext must not leave the client
            return false;
        }
        self.allowed_services.iter().any(|s| s == service_did)
    }

    /// Check if a message payload should be encrypted before sending.
    pub fn should_encrypt(&self, is_private: bool) -> bool {
        self.is_e2ee || (is_private && !self.allowed_services.is_empty())
    }
}

/// Validate a JSON value against a known schema name.
/// This is a lightweight structural check; full JSON Schema validation
/// would require a schema library.
pub fn validate_structure(value: &Value, schema_name: &str) -> Result<(), ValidationError> {
    match schema_name {
        "cursor" => validate_cursor_schema(value),
        "event" => validate_event_schema(value),
        "grant" => validate_grant_schema(value),
        "encrypted-envelope" => validate_encrypted_envelope_schema(value),
        _ => Err(ValidationError::UnknownSchema(schema_name.to_owned())),
    }
}

fn validate_cursor_schema(value: &Value) -> Result<(), ValidationError> {
    if !value.is_object() {
        return Err(ValidationError::ExpectedObject("cursor".into()));
    }
    let obj = value.as_object().unwrap();
    if !obj.contains_key("version") {
        return Err(ValidationError::MissingField("version".into()));
    }
    if !obj.contains_key("timestamp") {
        return Err(ValidationError::MissingField("timestamp".into()));
    }
    Ok(())
}

fn validate_event_schema(value: &Value) -> Result<(), ValidationError> {
    if !value.is_object() {
        return Err(ValidationError::ExpectedObject("event".into()));
    }
    let obj = value.as_object().unwrap();
    for field in &["operation_id", "space_id", "actor", "type", "causal"] {
        if !obj.contains_key(*field) {
            return Err(ValidationError::MissingField(field.to_string()));
        }
    }
    Ok(())
}

fn validate_grant_schema(value: &Value) -> Result<(), ValidationError> {
    if !value.is_object() {
        return Err(ValidationError::ExpectedObject("grant".into()));
    }
    let obj = value.as_object().unwrap();
    for field in &["grant_id", "issuer", "subject", "actions"] {
        if !obj.contains_key(*field) {
            return Err(ValidationError::MissingField(field.to_string()));
        }
    }
    Ok(())
}

fn validate_encrypted_envelope_schema(value: &Value) -> Result<(), ValidationError> {
    if !value.is_object() {
        return Err(ValidationError::ExpectedObject("encrypted-envelope".into()));
    }
    let obj = value.as_object().unwrap();
    for field in &["scheme", "version", "group_id", "epoch", "ciphertext"] {
        if !obj.contains_key(*field) {
            return Err(ValidationError::MissingField(field.to_string()));
        }
    }
    // Verify scheme is mls-rfc9420
    if obj.get("scheme").and_then(|v| v.as_str()) != Some("mls-rfc9420") {
        return Err(ValidationError::InvalidValue {
            field: "scheme".into(),
            expected: "mls-rfc9420".into(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    UnknownSchema(String),
    ExpectedObject(String),
    MissingField(String),
    InvalidValue { field: String, expected: String },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchema(s) => write!(f, "unknown schema: {s}"),
            Self::ExpectedObject(s) => write!(f, "{s}: expected object"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidValue { field, expected } => {
                write!(f, "invalid value for {field}, expected: {expected}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Discoverability levels per contrix-spec section 9.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Discoverability {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

/// Space discovery state per contrix-spec section 9.2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceDiscovery {
    pub discoverability: Discoverability,
    pub directory_visibility: String,
    #[serde(default)]
    pub preview_fields: Vec<String>,
    #[serde(default)]
    pub allowed_discoverers: Vec<String>,
    pub anti_enumeration: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn conformance_profiles_declared() {
        let profiles = known_profiles();
        assert!(
            profiles
                .iter()
                .any(|p| p.profile_id == "cx.profile.minimal_client.v1" && p.supported)
        );
        assert!(
            profiles
                .iter()
                .any(|p| p.profile_id == "cx.profile.full_client.v1" && !p.supported)
        );
    }

    #[test]
    fn plaintext_boundary_blocks_e2ee() {
        let boundary = PlaintextBoundary {
            allowed_services: vec!["did:web:server".into()],
            is_e2ee: true,
        };
        assert!(!boundary.can_send_plaintext("did:web:server"));
        assert!(boundary.should_encrypt(true));
    }

    #[test]
    fn plaintext_boundary_allows_non_e2ee_to_allowed() {
        let boundary = PlaintextBoundary {
            allowed_services: vec!["did:web:server".into()],
            is_e2ee: false,
        };
        assert!(boundary.can_send_plaintext("did:web:server"));
        assert!(!boundary.can_send_plaintext("did:web:other"));
    }

    #[test]
    fn validate_cursor_schema_ok() {
        let cursor = json!({"version": 1, "timestamp": "2026-01-01T00:00:00Z"});
        assert!(validate_structure(&cursor, "cursor").is_ok());
    }

    #[test]
    fn validate_cursor_schema_missing_field() {
        let cursor = json!({"version": 1});
        assert!(validate_structure(&cursor, "cursor").is_err());
    }

    #[test]
    fn validate_event_schema_ok() {
        let event = json!({
            "operation_id": "op1",
            "space_id": "cx:space:s1",
            "actor": "did:web:alice",
            "type": "cx.message.create",
            "causal": {"hlc": "0000018ef01234-00000001-deadbeef", "actor_seq": 1}
        });
        assert!(validate_structure(&event, "event").is_ok());
    }

    #[test]
    fn validate_encrypted_envelope_schema() {
        let envelope = json!({
            "scheme": "mls-rfc9420",
            "version": 1,
            "group_id": "g1",
            "epoch": 0,
            "ciphertext": "base64data"
        });
        assert!(validate_structure(&envelope, "encrypted-envelope").is_ok());

        let bad = json!({
            "scheme": "olm",
            "version": 1,
            "group_id": "g1",
            "epoch": 0,
            "ciphertext": "data"
        });
        assert!(validate_structure(&bad, "encrypted-envelope").is_err());
    }

    #[test]
    fn discoverability_round_trip() {
        let d = Discoverability::Public;
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, "\"public\"");
        let parsed: Discoverability = serde_json::from_str(&json).unwrap();
        assert_eq!(d, parsed);
    }
}
