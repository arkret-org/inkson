//! Conformance profiles, JSON schema validation, and security checks
//! per cokret-spec sections 12-13.

use std::sync::LazyLock;

use cokret_sdk::Discoverability;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{ServerDescription, ServerDescriptionExt};

pub const PROFILE_MINIMAL_CLIENT: &str = "ck.profile.minimal_client.v1";
// T2.3: chat_only_client / kanban_only_client profile ids were removed from
// the spec (artifacts/registry/deprecated-profile-ids.json, since 0a5ab85).
// Replacement profile ids are ck.profile.chat_mvp.v1 / ck.profile.kanban_mvp.v1;
// modality is otherwise expressed via Realm schema, not via single-modality
// profile gating.
pub const PROFILE_CHAT_MVP: &str = "ck.profile.chat_mvp.v1";
pub const PROFILE_KANBAN_MVP: &str = "ck.profile.kanban_mvp.v1";
pub const PROFILE_FULL_CLIENT: &str = "ck.profile.full_client.v1";
pub const PROFILE_E2EE_CLIENT: &str = "ck.profile.e2ee_client.v1";
pub const PROFILE_FEDERATION_MINIMAL: &str = "ck.profile.federation_minimal.v1";
// T0.3: push_gateway is a gateway role profile (not a client role). yougen
// is a client and MUST NOT declare itself as supporting the push_gateway
// profile (no entry in client_profile_declarations()). The constant is kept
// only so the settings panel can read whether the *server* advertises a
// push gateway endpoint.
pub const PROFILE_PUSH_GATEWAY: &str = "ck.profile.push_gateway.v1";
/// MLS Governance Binding hardening profile (`encryption-and-audit.md` §10).
///
/// Yougen ships the canonical event payload through
/// [`cokret_sdk::MlsGovernanceBindingPayload`] / [`cokret_sdk::MlsCommitPayload`],
/// and the `covered_seals_cell` add-effect through [`cokret_sdk::mls_move`].
/// The commit submit path remains gated on server features advertised via
/// [`crate::api::Api::events_describe`] before the profile reports `ready`.
pub const PROFILE_MLS_GOVERNANCE_BINDING_FULL: &str = "ck.profile.mls_governance_binding.full.v1";

/// Conformance profile declarations per cokret-spec section 13.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceProfile {
    pub profile_id: String,
    pub version: String,
    pub description: String,
    pub supported: bool,
    /// Profile tier label — "v1_core" or "v1.1+ extension".
    /// Mirrors `artifacts/profiles/conformance-profiles.json profile_tiers`.
    pub tier: String,
}

/// All known conformance profiles.
pub fn known_profiles() -> Vec<ConformanceProfile> {
    client_profile_declarations()
        .into_iter()
        .map(|declaration| ConformanceProfile {
            profile_id: declaration.profile_id.to_owned(),
            version: "1.0".to_owned(),
            description: declaration.description.to_owned(),
            supported: declaration.local_supported,
            tier: declaration.tier.label().to_owned(),
        })
        .collect()
}

/// Conformance tier per `artifacts/profiles/conformance-profiles.json` `profile_tiers`.
///
/// - `V1Core` — must be implemented to claim v1 conformance. 14 profiles total at the spec level;
///   yougen exposes the client-side subset.
/// - `V1_1Extension` — opt-in extension shipping after v1 core stable. Currently `applet_service`,
///   `agent_runtime`, `mimi_interop`. Implementations MAY declare these without violating v1 core
///   conformance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConformanceTier {
    V1Core,
    V1_1Extension,
}

impl ConformanceTier {
    pub fn label(self) -> &'static str {
        match self {
            Self::V1Core => "v1_core",
            Self::V1_1Extension => "v1.1+ extension",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientProfileDeclaration {
    pub profile_id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub local_supported: bool,
    pub degradation_path: &'static str,
    pub tier: ConformanceTier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileReadiness {
    pub profile_id: String,
    pub label: String,
    pub local_supported: bool,
    pub server_declared: bool,
    pub ready: bool,
    pub missing: Vec<String>,
    pub degradation_path: String,
}

pub fn client_profile_declarations() -> Vec<ClientProfileDeclaration> {
    vec![
        ClientProfileDeclaration {
            profile_id: PROFILE_MINIMAL_CLIENT,
            label: "minimal_client",
            description: "Minimal client: sync, directory lookup, Board, and plaintext message strand.",
            local_supported: true,
            degradation_path: "Read-only shell with server discovery and local cached state.",
            tier: ConformanceTier::V1Core,
        },
        ClientProfileDeclaration {
            profile_id: PROFILE_CHAT_MVP,
            label: "chat_mvp",
            description: "Chat MVP client: channels, message send/edit/redaction, reactions, and read markers.",
            local_supported: true,
            degradation_path: "Chat remains readable, but write controls stay gated.",
            tier: ConformanceTier::V1Core,
        },
        ClientProfileDeclaration {
            profile_id: PROFILE_KANBAN_MVP,
            label: "kanban_mvp",
            description: "Kanban MVP client: board/list/card projection and canonical write-plane mutations.",
            local_supported: true,
            degradation_path: "Directory/index projections remain available without board mutation controls.",
            tier: ConformanceTier::V1Core,
        },
        ClientProfileDeclaration {
            profile_id: PROFILE_FULL_CLIENT,
            label: "full_client",
            description: "Full client: setup workflows, Realm lifecycle, audit, notifications, app views, and admin surfaces.",
            local_supported: true,
            degradation_path: "Fall back to minimal, chat-only, and kanban-only surfaces.",
            tier: ConformanceTier::V1Core,
        },
        ClientProfileDeclaration {
            profile_id: PROFILE_E2EE_CLIENT,
            label: "e2ee_client",
            description: "E2EE client: MLS payload preservation, key lifecycle, device queues, and verification UX.",
            local_supported: true,
            degradation_path: "Use plaintext development mode and preserve encrypted payloads without claiming decryptability.",
            tier: ConformanceTier::V1Core,
        },
        ClientProfileDeclaration {
            profile_id: PROFILE_FEDERATION_MINIMAL,
            label: "federation_minimal",
            description: "Federation-minimal client: remote service DID display, transaction/backfill errors, and quarantine warnings.",
            local_supported: true,
            degradation_path: "Hide federation actions and show local-domain resources only.",
            tier: ConformanceTier::V1Core,
        },
        // T0.3: push_gateway profile is a gateway role, not a client role.
        // yougen is the client; it MUST NOT declare local_supported for the
        // push_gateway profile. The notification *projection* surface lives
        // in [`crate::push_registration`], but the client only registers
        // with the gateway and consumes its describe — it does not implement
        // the gateway role itself.
        ClientProfileDeclaration {
            profile_id: PROFILE_MLS_GOVERNANCE_BINDING_FULL,
            label: "mls_governance_binding_full",
            description: "MLS Governance Binding hardening: governance_binding payload + covered_seals_cell add-effect on every commit.",
            local_supported: true,
            degradation_path: "Fall back to baseline e2ee_client without binding governance seals to MLS commits.",
            tier: ConformanceTier::V1Core,
        },
        // ---- v1.1+ extensions ----
        // These three profiles are explicitly listed in
        // `artifacts/profiles/conformance-profiles.json` `profile_tiers
        // .v1_1_extension_implementation`. v1 core conformance does NOT
        // require them; servers that don't ship them stay v1 core compliant.
        ClientProfileDeclaration {
            profile_id: "ck.profile.applet_service.v1",
            label: "applet_service",
            description: "Applet integration: bridge / bot registration, ghost actor, portal Space (extensions/applet-integration).",
            local_supported: false,
            degradation_path: "Surface registry view-only; writes gated until server declares the extension.",
            tier: ConformanceTier::V1_1Extension,
        },
        ClientProfileDeclaration {
            profile_id: "ck.profile.agent_runtime.v1",
            label: "agent_runtime",
            description: "Agent runtime: A2A / ACP / MCP protocol session events (extensions/agent-protocol-interop).",
            local_supported: false,
            degradation_path: "Show agent capability claims read-only; do not initiate protocol sessions.",
            tier: ConformanceTier::V1_1Extension,
        },
        ClientProfileDeclaration {
            profile_id: "ck.profile.mimi_interop.v1",
            label: "mimi_interop",
            description: "MIMI interop: provider facade, room binding, ciphertext envelope (extensions/mimi-interop).",
            local_supported: false,
            degradation_path: "Treat MIMI rooms as opaque external Spaces; do not parse provider state.",
            tier: ConformanceTier::V1_1Extension,
        },
    ]
}

pub fn local_supported_profile_ids() -> Vec<&'static str> {
    client_profile_declarations()
        .into_iter()
        .filter(|declaration| declaration.local_supported)
        .map(|declaration| declaration.profile_id)
        .collect()
}

/// Canonical event kinds that yougen claims to emit / consume.
///
/// This list is used by:
/// - The explanatory panels in `views/audit.rs` / `views/realm_admin.rs`.
/// - Cross-references in `claude-design/` and `_todos.md`.
/// - Fixture seals for upcoming `tests/` end-to-end strands.
///
/// Spec sources: `overview/current-model.md`, `models/object-model-core.md`,
/// `models/object-model-standard.md` §5 (Strand / Message / edit and redact),
/// `crypto-media/device-lifecycle.md`, `authz/capabilities.md`,
/// `sync/operations-sync.md`, `crypto-media/encryption-and-audit.md`,
/// `crypto-media/audited-e2ee.md` (attested / disclosed audit profile),
/// `crypto-media/webrtc-signaling.md`, `extensions/applet-integration.md`,
/// `extensions/agent-protocol-interop.md`, `extensions/mimi-interop.md`.
/// Canonical registry: `artifacts/registry/event-kind-registry.json`.
pub fn known_event_kinds() -> Vec<&'static str> {
    cokret_sdk::events::kinds::STANDARD_EVENT_KINDS.to_vec()
}
/// `wire_scope` classification for canonical event kinds — mirrors
/// `wire_scope_definitions` in `event-kind-registry.json`.
///
/// - `Durable` — written into Space history; reducer input.
/// - `ActorPrivate` — actor-scoped; reducer input but not shared into the Space.
/// - `Ephemeral` — short-TTL signaling; reducer MUST NOT use as state input.
///
/// The chat / call / verification views use this to keep ephemeral signals
/// from being rendered as durable history. The classification delegates to
/// `cokret_sdk::events::kinds::event_wire_scope`, so wire-scope facts come
/// from the SDK's spec-sync surface instead of a yougen-local mirror.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKindWireScope {
    Durable,
    ActorPrivate,
    Ephemeral,
}

impl EventKindWireScope {
    pub fn as_registry_str(self) -> &'static str {
        match self {
            Self::Durable => "durable_event",
            Self::ActorPrivate => "actor_private_event",
            Self::Ephemeral => "ephemeral_event",
        }
    }

    pub fn from_registry_str(value: &str) -> Option<Self> {
        match value {
            "durable_event" => Some(Self::Durable),
            "actor_private_event" => Some(Self::ActorPrivate),
            "ephemeral_event" => Some(Self::Ephemeral),
            _ => None,
        }
    }
}

fn known_event_kind_slice() -> &'static [&'static str] {
    static KNOWN_EVENT_KINDS: LazyLock<Vec<&'static str>> = LazyLock::new(known_event_kinds);
    KNOWN_EVENT_KINDS.as_slice()
}

fn sdk_wire_scope(event_kind: &str) -> Option<EventKindWireScope> {
    match cokret_sdk::events::kinds::event_wire_scope(event_kind) {
        cokret_sdk::events::kinds::EventWireScope::DurableEvent => {
            Some(EventKindWireScope::Durable)
        }
        cokret_sdk::events::kinds::EventWireScope::ActorPrivateEvent => {
            Some(EventKindWireScope::ActorPrivate)
        }
        cokret_sdk::events::kinds::EventWireScope::EphemeralEvent => {
            Some(EventKindWireScope::Ephemeral)
        }
        cokret_sdk::events::kinds::EventWireScope::Custom => None,
    }
}

/// F-PROFILE-1: cheap fast-path version of "is `kind` in
/// [`known_event_kinds()`]?" used by inbound event-parse gates.
///
/// Spec `conformance/conformance-profiles.md §2` says implementations
/// MUST reject events whose `kind` is outside the profile they declared
/// — yougen's profile surface lives in [`known_event_kinds()`], so any
/// kind absent from that list is by definition out-of-profile and a
/// likely sign of either a buggy server, a profile-drift attack, or a
/// spec bump that yougen hasn't picked up yet.
///
/// Returns `true` for every kind yougen typed (durable / actor-private
/// / ephemeral); returns `false` for unknown kinds. Reducer / sync
/// entry points should call [`require_known_event_kind`] to convert
/// the rejection into a [`ValidationError`].
pub fn is_known_event_kind(event_kind: &str) -> bool {
    event_kind_wire_scope(event_kind).is_some()
}

/// F-PROFILE-1: stricter sibling of [`is_known_event_kind`] that
/// returns a [`ValidationError::UnknownEventKind`] for kinds outside
/// the conformance profile. Use at event ingest boundaries (sync
/// engine event-stream dispatch, fixture parsers, reducer input
/// validation) so an unknown kind aborts processing instead of
/// falling through to a default branch.
pub fn require_known_event_kind(event_kind: &str) -> Result<(), ValidationError> {
    if is_known_event_kind(event_kind) {
        Ok(())
    } else {
        Err(ValidationError::UnknownEventKind(event_kind.to_owned()))
    }
}

/// Returns the canonical `wire_scope` for `event_kind`, or `None` when the
/// kind is unknown to yougen. Unknown kinds default to "treat as durable" at
/// the call site so we never leak signaling into a state path by accident.
pub fn event_kind_wire_scope(event_kind: &str) -> Option<EventKindWireScope> {
    if known_event_kind_slice().contains(&event_kind) {
        return sdk_wire_scope(event_kind);
    }
    None
}

/// All event kinds yougen currently classifies as ephemeral signaling. The
/// chat/call views use this to render their "ephemeral signals" banners
/// programmatically rather than re-typing kind literals.
pub fn ephemeral_event_kinds() -> &'static [&'static str] {
    static EPHEMERAL_EVENT_KINDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        known_event_kind_slice()
            .iter()
            .copied()
            .filter(|kind| sdk_wire_scope(kind) == Some(EventKindWireScope::Ephemeral))
            .collect()
    });
    EPHEMERAL_EVENT_KINDS.as_slice()
}

/// All event kinds yougen currently classifies as actor-private.
pub fn actor_private_event_kinds() -> &'static [&'static str] {
    static ACTOR_PRIVATE_EVENT_KINDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        known_event_kind_slice()
            .iter()
            .copied()
            .filter(|kind| sdk_wire_scope(kind) == Some(EventKindWireScope::ActorPrivate))
            .collect()
    });
    ACTOR_PRIVATE_EVENT_KINDS.as_slice()
}

pub fn profile_readiness(server: Option<&ServerDescription>) -> Vec<ProfileReadiness> {
    client_profile_declarations()
        .into_iter()
        .map(|declaration| {
            let server_declared = server.is_some_and(|description| {
                description
                    .supported_profiles
                    .iter()
                    .any(|profile| profile == declaration.profile_id)
            });
            let missing = server
                .map(|description| missing_requirements(declaration.profile_id, description))
                .unwrap_or_else(|| vec!["server describe unavailable".to_owned()]);
            let ready = declaration.local_supported && missing.is_empty();

            ProfileReadiness {
                profile_id: declaration.profile_id.to_owned(),
                label: declaration.label.to_owned(),
                local_supported: declaration.local_supported,
                server_declared,
                ready,
                missing,
                degradation_path: declaration.degradation_path.to_owned(),
            }
        })
        .collect()
}

pub fn profile_ready(server: Option<&ServerDescription>, profile_id: &str) -> bool {
    server
        .map(|description| {
            description.supports_profile(profile_id)
                || missing_requirements(profile_id, description).is_empty()
        })
        .unwrap_or(true)
}

/// Diff a profile's `required_operations` (per the SDK's canonical
/// `profile_requirements` table — itself generated from
/// `cokret-spec/artifacts/profiles/`) against what the server
/// advertises in `supported_operations`. Profiles unknown to the SDK
/// table return a single sentinel so the UI surfaces "this profile id
/// isn't in the spec" rather than silently passing.
///
/// `required_event_kinds` / `required_schemas` are intentionally NOT
/// checked here — those describe what the *client* must implement,
/// not what the server has to expose. The server-side gate is about
/// "can I call the endpoints I'd need" only.
fn missing_requirements(profile_id: &str, server: &ServerDescription) -> Vec<String> {
    let Some(req) = cokret_sdk::generated::profile_requirements::requirements_for(profile_id)
    else {
        return vec![format!("unknown profile {profile_id}")];
    };
    req.required_operations
        .iter()
        .filter(|operation| !server.supports_operation(operation))
        .map(|operation| (*operation).to_owned())
        .collect()
}

/// Plaintext boundary check per cokret-spec section 12.1.
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
            // E2EE Realms: plaintext must not leave the client
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
    let Some(obj) = value.as_object() else {
        return Err(ValidationError::ExpectedObject("cursor".into()));
    };
    if !obj.contains_key("version") {
        return Err(ValidationError::MissingField("version".into()));
    }
    if !obj.contains_key("timestamp") {
        return Err(ValidationError::MissingField("timestamp".into()));
    }
    Ok(())
}

fn validate_event_schema(value: &Value) -> Result<(), ValidationError> {
    let Some(obj) = value.as_object() else {
        return Err(ValidationError::ExpectedObject("event".into()));
    };
    for field in &[
        "event_id",
        "kind",
        "realm_id",
        "actor_id",
        "actor_seq",
        "created_at",
        "prev_refs",
        "refs",
        "payload",
        "proofs",
    ] {
        if !obj.contains_key(*field) {
            return Err(ValidationError::MissingField(field.to_string()));
        }
    }
    // F-PROFILE-1: enforce the conformance profile by rejecting any
    // `kind` outside `known_event_kinds()`.
    // The schema-level shape check above already guarantees `kind` is
    // present; here we ensure it's also a kind yougen is qualified
    // to apply.
    if let Some(kind) = obj.get("kind").and_then(|v| v.as_str()) {
        require_known_event_kind(kind)?;
    }
    Ok(())
}

fn validate_grant_schema(value: &Value) -> Result<(), ValidationError> {
    let Some(obj) = value.as_object() else {
        return Err(ValidationError::ExpectedObject("grant".into()));
    };
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
    cokret_sdk::EncryptedEnvelopeV1::parse_and_validate(value.clone())
        .map(|_| ())
        .map_err(|_| ValidationError::InvalidValue {
            field: "encrypted-envelope".into(),
            expected: "ck.schema.encrypted_envelope.v1".into(),
        })
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("unknown schema: {0}")]
    UnknownSchema(String),
    #[error("{0}: expected object")]
    ExpectedObject(String),
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("invalid value for {field}, expected: {expected}")]
    InvalidValue { field: String, expected: String },
    /// F-PROFILE-1: the event's `kind` is not in the conformance profile
    /// yougen advertises (see [`known_event_kinds`]). Surfaces as a
    /// rejection at event ingest so a profile-drift attack / spec bump
    /// can't smuggle an unknown reducer kind into local state.
    #[error("event kind `{0}` is outside yougen's conformance profile")]
    UnknownEventKind(String),
}

/// Realm discovery state per cokret-spec section 9.2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmDiscovery {
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
    use serde_json::json;

    use super::*;

    #[test]
    fn conformance_profiles_declared() {
        let profiles = known_profiles();
        assert!(
            profiles
                .iter()
                .any(|p| p.profile_id == "ck.profile.minimal_client.v1" && p.supported)
        );
        assert!(
            profiles
                .iter()
                .any(|p| p.profile_id == "ck.profile.chat_mvp.v1" && p.supported)
        );
        // T0.3: yougen is a client, push_gateway is a gateway role — it
        // MUST NOT appear in the client's supported profile set.
        assert!(
            !profiles
                .iter()
                .any(|p| p.profile_id == "ck.profile.push_gateway.v1")
        );
    }

    #[test]
    fn profile_readiness_reports_server_gaps() {
        // Server advertises exactly the operations SDK's
        // `requirements_for(PROFILE_MINIMAL_CLIENT)` requires — minimal
        // client should be ready. `chat_mvp` additionally requires
        // `ck.self.account.stream.subscribe` which the fixture intentionally omits, so
        // the readiness gate flags it as missing.
        let server: ServerDescription = serde_json::from_value(json!({
            "service_did": "did:web:server.example",
            "trust_domain": "ck:trust_domain:server.example",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [PROFILE_MINIMAL_CLIENT],
            "supported_features": [],
            "supported_operations": [
                "ck.self.events.resource.get",
                "ck.self.events.query.scan",
                "ck.server.query.describe",
            ],
            "supported_bindings": [],
            // SDK AuthMetadata.mode is required (no default) — the fixture
            // must carry a concrete auth mode.
            "auth_metadata": {"mode": "development"},
            "limits": {},
            "plaintext_visibility": {"default": "encrypted"},
            "implemented_features": [],
            "claimed_profiles": [],
            "verified_profiles": [],
            "experimental_features": [],
            "compat_surfaces": [],
            "development_mode": false,
        }))
        .unwrap();

        let readiness = profile_readiness(Some(&server));
        let minimal = readiness
            .iter()
            .find(|profile| profile.profile_id == PROFILE_MINIMAL_CLIENT)
            .unwrap();
        assert!(minimal.ready, "missing: {:?}", minimal.missing);
        assert!(minimal.server_declared);

        let chat = readiness
            .iter()
            .find(|profile| profile.profile_id == PROFILE_CHAT_MVP)
            .unwrap();
        assert!(!chat.ready);
        assert!(
            chat.missing
                .iter()
                .any(|missing| missing.contains("ck.self.account.stream.subscribe")),
            "expected chat_mvp to flag missing ck.self.account.stream.subscribe, got {:?}",
            chat.missing
        );
    }

    #[test]
    fn profile_ready_is_permissive_until_describe_finishes() {
        assert!(profile_ready(None, PROFILE_CHAT_MVP));
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
            "event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "kind": "ck.message.create",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice",
            "actor_seq": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "prev_refs": [],
            "refs": [],
            "payload": {},
            "proofs": []
        });
        assert!(validate_structure(&event, "event").is_ok());
    }

    /// F-PROFILE-1: an otherwise well-formed event whose `kind` falls
    /// outside `known_event_kinds()` must be rejected at the validate
    /// boundary instead of being treated as a "default" branch later.
    #[test]
    fn validate_event_schema_rejects_unknown_kind() {
        let event = json!({
            "event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "kind": "ck.bogus.kind",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice",
            "actor_seq": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "prev_refs": [],
            "refs": [],
            "payload": {},
            "proofs": []
        });
        match validate_structure(&event, "event") {
            Err(ValidationError::UnknownEventKind(kind)) => {
                assert_eq!(kind, "ck.bogus.kind");
            }
            other => panic!("expected UnknownEventKind, got {other:?}"),
        }
    }

    #[test]
    fn require_known_event_kind_accepts_canonical_and_rejects_garbage() {
        assert!(require_known_event_kind("ck.message.create").is_ok());
        assert!(require_known_event_kind("ck.strand.update").is_ok());
        assert!(require_known_event_kind("ck.typing").is_ok());
        let err = require_known_event_kind("ck.bogus.kind").expect_err("unknown kind must error");
        assert!(matches!(err, ValidationError::UnknownEventKind(_)));
    }

    #[test]
    fn validate_encrypted_envelope_schema() {
        let envelope = json!({
            "scheme": "mls-rfc9420",
            "version": "1.0",
            "group_id": "Z3JvdXA",
            "epoch": 0,
            "content_type": "application/json",
            "ciphertext": "Y2lwaGVydGV4dA",
            "aad_visibility_event_id": "hidden",
            "aad": {
                "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
                "event_kind": "ck.message.create"
            },
            "key_ref": {
                "algorithm": "MLS",
                "group_state_ref": "ck:event:01904100-0000-7000-8000-000000000001"
            },
            "aad_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        });
        assert!(validate_structure(&envelope, "encrypted-envelope").is_ok());

        let exporter = json!({
            "scheme": "mls-exporter-aead-v1",
            "version": "1.0",
            "group_id": "Z3JvdXA",
            "epoch": 0,
            "content_type": "application/json",
            "ciphertext": "Y2lwaGVydGV4dA",
            "aad_visibility_event_id": "hidden",
            "aad": {
                "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
                "event_kind": "ck.message.create"
            },
            "key_ref": {
                "algorithm": "MLS-EXPORTER-AEAD",
                "group_state_ref": "ck:event:01904100-0000-7000-8000-000000000001"
            },
            "aad_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        });
        assert!(validate_structure(&exporter, "encrypted-envelope").is_ok());

        let mut bad = exporter.clone();
        bad["key_ref"]["algorithm"] = json!("MLS");
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

    #[test]
    fn known_event_kinds_covers_load_bearing_kinds() {
        let kinds = known_event_kinds();
        // current-model §3 — unified track update (spec dc01ad7)
        assert!(kinds.contains(&"ck.strand.tracks.update"));
        // Split track events were removed in the dc01ad7 unification.
        assert!(!kinds.contains(&"ck.strand.track.enable"));
        assert!(!kinds.contains(&"ck.strand.track.disable"));
        assert!(!kinds.contains(&"ck.strand.track.update"));
        assert!(!kinds.contains(&"ck.strand.track.set_primary"));
        // current-model §4 — board / list workflow container
        assert!(kinds.contains(&"ck.strand.move"));
        assert!(kinds.contains(&"ck.strand.reorder"));
        // device-lifecycle §1.2 (login / authorization / verification three axes)
        assert!(kinds.contains(&"ck.session.grant"));
        assert!(kinds.contains(&"ck.device.authorize"));
        assert!(kinds.contains(&"ck.device.revoke"));
        // device-lifecycle §7-§9 verification ceremony events.
        assert!(kinds.contains(&"ck.key.verification.start"));
        assert!(kinds.contains(&"ck.key.verification.done"));
        // discovery/read-receipts §6 — read marker is a wire event,
        // notification is *not* (it's a derived projection).
        assert!(kinds.contains(&"ck.read_cursor.advance"));
        assert!(kinds.contains(&"ck.receipt.read"));
        assert!(!kinds.contains(&"ck.notification.dismiss"));
        // audited-e2ee — attested + disclosed audit profiles
        assert!(kinds.contains(&"ck.audit.accessed"));
        assert!(kinds.contains(&"ck.audit.ryw_receipt"));
        // Removed by spec
        assert!(!kinds.contains(&"ck.strand.convert"));
        assert!(!kinds.contains(&"ck.mls.epoch"));
        // T2.3 (spec 0a5ab85): single 'set' kinds were decomposed into
        // per-component cells / typed lifecycle events.
        assert!(!kinds.contains(&"ck.space.lifecycle.set"));
        assert!(!kinds.contains(&"ck.space.policy.set"));
        // Realm/Space split: security-boundary events live in ck.realm.*;
        // container lifecycle events live in ck.space.*.
        assert!(kinds.contains(&"ck.realm.create"));
        assert!(kinds.contains(&"ck.realm.update"));
        assert!(kinds.contains(&"ck.space.archive"));
        assert!(kinds.contains(&"ck.space.restore"));
        assert!(kinds.contains(&"ck.space.tombstone"));
        // Renamed: ck.actor.profile.update -> ck.profile.update
        assert!(kinds.contains(&"ck.profile.update"));
        assert!(!kinds.contains(&"ck.actor.profile.update"));
    }

    #[test]
    fn known_event_kinds_have_protocol_namespace() {
        for kind in known_event_kinds() {
            assert!(
                kind.starts_with("ck."),
                "event kind `{kind}` must live in the ck.* namespace"
            );
            assert!(
                !kind.contains(' '),
                "event kind `{kind}` must not contain spaces"
            );
        }
    }

    /// Lock-down: every entry in `known_event_kinds()` is unique.
    ///
    /// Drift detector — if a refactor accidentally double-listed an event
    /// kind, this catches it before it ships into the conformance surface.
    #[test]
    fn known_event_kinds_are_unique() {
        let kinds = known_event_kinds();
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for k in &kinds {
            assert!(
                seen.insert(k),
                "duplicate event kind in known_event_kinds(): `{k}`"
            );
        }
    }

    /// Lock-down: structural shape of each event kind.
    ///
    /// All canonical event kinds follow the segment pattern `ck.<group>.<verb>[.<sub>]…`
    /// with lowercase ASCII + underscore; payloads in identifiers are forbidden.
    #[test]
    fn known_event_kinds_are_well_formed() {
        for kind in known_event_kinds() {
            for (i, segment) in kind.split('.').enumerate() {
                assert!(
                    !segment.is_empty(),
                    "event kind `{kind}` has empty segment at index {i}"
                );
                for ch in segment.chars() {
                    assert!(
                        ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_',
                        "event kind `{kind}` has illegal char `{ch}` in segment `{segment}`"
                    );
                }
            }
        }
    }

    #[test]
    fn known_event_kinds_have_no_duplicates() {
        let kinds = known_event_kinds();
        let mut sorted = kinds.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            kinds.len(),
            "event kind list must contain no duplicates"
        );
    }

    #[test]
    fn ephemeral_kinds_never_classify_as_durable() {
        for kind in super::ephemeral_event_kinds() {
            let scope = super::event_kind_wire_scope(kind);
            assert_eq!(
                scope,
                Some(super::EventKindWireScope::Ephemeral),
                "ephemeral kind `{kind}` must classify as Ephemeral; \
                 leaking into Durable would let a reducer state-track signaling"
            );
        }
    }

    #[test]
    fn actor_private_kinds_classify_consistently() {
        for kind in super::actor_private_event_kinds() {
            assert_eq!(
                super::event_kind_wire_scope(kind),
                Some(super::EventKindWireScope::ActorPrivate)
            );
        }
    }

    #[test]
    fn event_kind_wire_scope_returns_none_for_unknown_kind() {
        assert_eq!(super::event_kind_wire_scope("ck.bogus.kind"), None);
    }
}
