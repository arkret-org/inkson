//! Conformance profiles, JSON schema validation, and security checks
//! per contrix-spec sections 12–13.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::ServerDescription;

pub const PROFILE_MINIMAL_CLIENT: &str = "cx.profile.minimal_client.v1";
pub const PROFILE_CHAT_ONLY_CLIENT: &str = "cx.profile.chat_only_client.v1";
pub const PROFILE_KANBAN_ONLY_CLIENT: &str = "cx.profile.kanban_only_client.v1";
pub const PROFILE_FULL_CLIENT: &str = "cx.profile.full_client.v1";
pub const PROFILE_E2EE_CLIENT: &str = "cx.profile.e2ee_client.v1";
pub const PROFILE_FEDERATION_MINIMAL: &str = "cx.profile.federation_minimal.v1";
pub const PROFILE_PUSH_GATEWAY: &str = "cx.profile.push_gateway.v1";

/// Conformance profile declarations per contrix-spec section 13.1.
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

/// Conformance tier per `artifacts/profiles/conformance-profiles.json` `profile_tiers`
/// (Round 3 of the 2026-05-05 spec simplification).
///
/// - `V1Core` — must be implemented to claim v1 conformance. 14 profiles total at
///   the spec level; yougen exposes the client-side subset.
/// - `V1_1Extension` — opt-in extension shipping after v1 core stable. Currently
///   `applet_service`, `agent_runtime`, `mimi_interop`. Implementations MAY
///   declare these without violating v1 core conformance.
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
            description: "Minimal client: sync, directory lookup, timeline, and plaintext message flow.",
            local_supported: true,
            degradation_path: "Read-only shell with server discovery and local cached state.",
            tier: ConformanceTier::V1Core,
        },
        ClientProfileDeclaration {
            profile_id: PROFILE_CHAT_ONLY_CLIENT,
            label: "chat_only_client",
            description: "Chat-only client: channels, timeline, message send/edit/redaction, reactions, and read markers.",
            local_supported: true,
            degradation_path: "Timeline can remain visible, but chat write controls stay gated.",
            tier: ConformanceTier::V1Core,
        },
        ClientProfileDeclaration {
            profile_id: PROFILE_KANBAN_ONLY_CLIENT,
            label: "kanban_only_client",
            description: "Kanban-only client: board/list/card projection and repo-backed entity operations.",
            local_supported: true,
            degradation_path: "Directory/index projections remain available without board mutation controls.",
            tier: ConformanceTier::V1Core,
        },
        ClientProfileDeclaration {
            profile_id: PROFILE_FULL_CLIENT,
            label: "full_client",
            description: "Full client: product workflows, space lifecycle, audit, notifications, app views, and admin surfaces.",
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
        ClientProfileDeclaration {
            profile_id: PROFILE_PUSH_GATEWAY,
            label: "push_gateway",
            description: "Push gateway client: chime registration, unregister, local push state, and notification projection.",
            local_supported: true,
            degradation_path: "Keep in-app notification projection and skip push registration controls.",
            tier: ConformanceTier::V1Core,
        },
        // ---- v1.1+ extensions ----
        // These three profiles are explicitly listed in
        // `artifacts/profiles/conformance-profiles.json` `profile_tiers
        // .v1_1_extension_implementation`. v1 core conformance does NOT
        // require them; servers that don't ship them stay v1 core compliant.
        ClientProfileDeclaration {
            profile_id: "cx.profile.applet_service.v1",
            label: "applet_service",
            description: "Applet integration: bridge / bot registration, ghost actor, portal Space (extensions/applet-integration).",
            local_supported: false,
            degradation_path: "Surface registry view-only; writes gated until server declares the extension.",
            tier: ConformanceTier::V1_1Extension,
        },
        ClientProfileDeclaration {
            profile_id: "cx.profile.agent_runtime.v1",
            label: "agent_runtime",
            description: "Agent runtime: A2A / ACP / MCP protocol session events (extensions/agent-protocol-interop).",
            local_supported: false,
            degradation_path: "Show agent capability claims read-only; do not initiate protocol sessions.",
            tier: ConformanceTier::V1_1Extension,
        },
        ClientProfileDeclaration {
            profile_id: "cx.profile.mimi_interop.v1",
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
/// 该列表用于：
/// - `views/audit.rs` / `views/space_admin.rs` 的解释面板。
/// - `claude-design/` 与 `_todos.md` 的 cross-reference。
/// - 后续 `tests/` 端到端流程的 fixture 锚点。
///
/// 协议来源：`overview/current-model.md`、`models/object-model-core.md`、
/// `models/object-model-standard.md` §5（Flow / Message / 编辑撤回）、
/// `crypto-media/device-lifecycle.md`、`authz/capabilities.md`、
/// `sync/operations-sync.md`、`crypto-media/encryption-and-audit.md`、
/// `crypto-media/audited-e2ee.md`（attested / disclosed audit profile）、
/// `crypto-media/webrtc-signaling.md`、`extensions/applet-integration.md`、
/// `extensions/agent-protocol-interop.md`、`extensions/mimi-interop.md`。
/// canonical registry: `artifacts/registry/event-kind-registry.json`（109 active kinds）。
pub fn known_event_kinds() -> Vec<&'static str> {
    // 109 active wire event kinds, mirrored from
    // `artifacts/registry/event-kind-registry.json` (commit fc7da5b, 2026-05-05).
    // ORDER MATTERS for diff-friendly maintenance: keep alphabetical inside each
    // group. When the spec adds/removes a kind, update both this list and the
    // registry test below.
    vec![
        // Account / actor profile
        "cx.account.blocklist",
        "cx.account.status",
        "cx.account_data.set",
        "cx.profile.update",
        "cx.profile.space_override",
        // Agent (extensions/agent-protocol-interop — v1.1+ but kinds are core)
        "cx.agent.endpoint",
        "cx.agent.protocol_session.result",
        "cx.agent.protocol_session.start",
        "cx.agent.protocol_session.status",
        // Applet (extensions/applet-integration — v1.1+ but kinds are core)
        "cx.applet.bridge_error",
        "cx.applet.protocol_session.start",
        "cx.applet.protocol_session.status",
        "cx.applet.registration",
        // Audited E2EE (crypto-media/audited-e2ee.md)
        "cx.audit.accessed",
        "cx.audit.ryw_receipt",
        // WebRTC call (crypto-media/webrtc-signaling)
        "cx.call.recording.start",
        "cx.call.signal",
        "cx.call.state",
        // Capability (authz/capabilities)
        "cx.capability.delegate",
        "cx.capability.derived",
        "cx.capability.grant",
        "cx.capability.revoke",
        // Container / position edge (board/list rebalance)
        "cx.container.move_item",
        "cx.container.rebalance",
        // Devices (crypto-media/device-lifecycle)
        "cx.device.authorized",
        "cx.device.list_update",
        "cx.device.revoked",
        // Identity (DID proof + progressive disclosure §16)
        "cx.did.proof",
        "cx.identity.disclosure_policy",
        "cx.identity.disclosure_receipt",
        "cx.identity.presentation_request",
        "cx.identity.presentation_response",
        // Flow / branch (current-model §3-§4)
        "cx.flow.archive",
        "cx.flow.branch.disable",
        "cx.flow.branch.enable",
        "cx.flow.branch.history_visibility",
        "cx.flow.branch.member",
        "cx.flow.branch.policy_components",
        "cx.flow.branch.set_primary",
        "cx.flow.branch.update",
        "cx.flow.create",
        "cx.flow.move",
        "cx.flow.reorder",
        "cx.flow.restore",
        "cx.flow.update",
        // Invite (sync/third-party-invites + identity/invites)
        "cx.invite.accept",
        "cx.invite.cancel",
        "cx.invite.claim",
        "cx.invite.create",
        "cx.invite.revoke",
        "cx.invite.third_party",
        // Key verification (device-lifecycle §7-§9)
        "cx.key.verification.accept",
        "cx.key.verification.cancel",
        "cx.key.verification.done",
        "cx.key.verification.key",
        "cx.key.verification.mac",
        "cx.key.verification.ready",
        "cx.key.verification.request",
        "cx.key.verification.start",
        // Membership
        "cx.member.state",
        // Message (object-model-standard §5.1-§5.3)
        "cx.message.create",
        "cx.message.redact",
        "cx.message.revise",
        // MIMI interop (extensions/mimi-interop — v1.1+)
        "cx.mimi.room_binding",
        // MLS (encryption-and-audit)
        "cx.mls.commit",
        "cx.mls.commit_failed",
        "cx.mls.genesis",
        "cx.mls.keypackage",
        "cx.mls.proposal",
        "cx.mls.welcome",
        // Moderation (governance/content-moderation)
        "cx.moderation.frank",
        "cx.moderation.report",
        // Morph
        "cx.morph.archive",
        "cx.morph.create",
        "cx.morph.restore",
        "cx.morph.update",
        // Organization (identity-did §6 + content-moderation)
        "cx.organization.discovery",
        "cx.organization.moderation_policy",
        // Policy (authz/policy-server)
        "cx.policy.action",
        "cx.policy.rule",
        "cx.policy.set",
        // Presence / typing (discovery/profiles-presence)
        "cx.presence",
        "cx.typing",
        // Reaction
        "cx.reaction.add",
        "cx.reaction.remove",
        // Read receipts / markers (discovery/read-receipts §6 — replaces
        // legacy read-notification-schema; notification itself is a *derived*
        // projection, not a canonical event).
        "cx.read.marker",
        "cx.receipt.read",
        // Redaction (cross-object — separate from cx.message.redact)
        "cx.redaction",
        // Relation
        "cx.relation.create",
        "cx.relation.delete",
        "cx.relation.update",
        // Schema evolution
        "cx.schema.define",
        "cx.schema.update",
        // Session grant (device-lifecycle §1.2)
        "cx.session.grant",
        // Sovereign deployment (sync/sovereign-deployment)
        "cx.sovereign.did_policy",
        // Space / boundary
        "cx.space.child",
        "cx.space.create",
        "cx.space.lifecycle.set",
        "cx.space.organization",
        "cx.space.parent",
        "cx.space.policy.set",
        "cx.space.update",
        "cx.space.upgrade",
        // MLS Space-key share (audited E2EE)
        "cx.space_key.share",
        "cx.space_key.share_audit",
        "cx.space_key.withheld",
        // View (View projection)
        "cx.view.create",
        "cx.view.reconcile",
        "cx.view.update",
    ]
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
        .map(|description| missing_requirements(profile_id, description).is_empty())
        .unwrap_or(true)
}

fn missing_requirements(profile_id: &str, server: &ServerDescription) -> Vec<String> {
    let mut missing = Vec::new();
    match profile_id {
        PROFILE_MINIMAL_CLIENT => {
            require_feature_or_operation(
                server,
                "sync.client_sync",
                "cx.sync.client_sync",
                &mut missing,
            );
            require_feature_or_operation(
                server,
                "directory.search_spaces",
                "cx.directory.search_spaces",
                &mut missing,
            );
        }
        PROFILE_CHAT_ONLY_CLIENT => {
            require_feature_or_operation(
                server,
                "sync.client_sync",
                "cx.sync.client_sync",
                &mut missing,
            );
            require_feature_or_operation(server, "message.send", "cx.messages.send", &mut missing);
        }
        PROFILE_KANBAN_ONLY_CLIENT => {
            require_feature_or_operation(server, "index.query", "cx.index.query", &mut missing);
            require_feature_or_operation(
                server,
                "repo.submit_commit",
                "cx.repo.submit_commit",
                &mut missing,
            );
        }
        PROFILE_FULL_CLIENT => {
            for (feature, operation) in [
                ("sync.client_sync", "cx.sync.client_sync"),
                ("directory.search_spaces", "cx.directory.search_spaces"),
                ("index.query", "cx.index.query"),
                ("repo.submit_commit", "cx.repo.submit_commit"),
                ("authz.check", "cx.authz.check"),
                ("space.create", "cx.spaces.create"),
            ] {
                require_feature_or_operation(server, feature, operation, &mut missing);
            }
        }
        PROFILE_E2EE_CLIENT => {
            for (feature, operation) in [
                ("keys.upload", "cx.keys.upload"),
                ("keys.query", "cx.keys.query"),
                ("keys.claim", "cx.keys.claim"),
                ("device_messages.receive", "cx.device_messages.receive"),
            ] {
                require_feature_or_operation(server, feature, operation, &mut missing);
            }
        }
        PROFILE_FEDERATION_MINIMAL => {
            require_feature_or_operation(
                server,
                "federation.transaction",
                "cx.federation.transaction",
                &mut missing,
            );
        }
        PROFILE_PUSH_GATEWAY => {
            require_feature_or_operation(
                server,
                "push.register_device",
                "cx.push.register_device",
                &mut missing,
            );
        }
        _ => missing.push(format!("unknown profile {profile_id}")),
    }
    missing
}

fn require_feature_or_operation(
    server: &ServerDescription,
    feature: &str,
    operation: &str,
    missing: &mut Vec<String>,
) {
    if !server.supports_feature(feature) && !server.supports_operation(operation) {
        missing.push(format!("{feature} or {operation}"));
    }
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
                .any(|p| p.profile_id == "cx.profile.chat_only_client.v1" && p.supported)
        );
        assert!(
            profiles
                .iter()
                .any(|p| p.profile_id == "cx.profile.push_gateway.v1")
        );
    }

    #[test]
    fn profile_readiness_reports_server_gaps() {
        let server: ServerDescription = serde_json::from_value(json!({
            "service_did": "did:web:server.example",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [PROFILE_MINIMAL_CLIENT],
            "supported_features": ["sync.client_sync", "directory.search_spaces"],
            "supported_operations": ["cx.sync.client_sync", "cx.directory.search_spaces"]
        }))
        .unwrap();

        let readiness = profile_readiness(Some(&server));
        let minimal = readiness
            .iter()
            .find(|profile| profile.profile_id == PROFILE_MINIMAL_CLIENT)
            .unwrap();
        assert!(minimal.ready);
        assert!(minimal.server_declared);

        let chat = readiness
            .iter()
            .find(|profile| profile.profile_id == PROFILE_CHAT_ONLY_CLIENT)
            .unwrap();
        assert!(!chat.ready);
        assert!(
            chat.missing
                .iter()
                .any(|missing| missing.contains("message.send"))
        );
    }

    #[test]
    fn profile_ready_is_permissive_until_describe_finishes() {
        assert!(profile_ready(None, PROFILE_CHAT_ONLY_CLIENT));
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

    #[test]
    fn known_event_kinds_matches_registry_count() {
        // Registry pinned to 109 active wire event kinds at commit fc7da5b.
        // Bumping the count here in lockstep with the spec is intentional —
        // it is a tripwire when the registry drifts under us.
        assert_eq!(known_event_kinds().len(), 109);
    }

    #[test]
    fn known_event_kinds_covers_load_bearing_kinds() {
        let kinds = known_event_kinds();
        // current-model §3 — branch lifecycle events
        assert!(kinds.contains(&"cx.flow.branch.enable"));
        assert!(kinds.contains(&"cx.flow.branch.set_primary"));
        // current-model §4 — board / list workflow container
        assert!(kinds.contains(&"cx.flow.move"));
        assert!(kinds.contains(&"cx.flow.reorder"));
        // device-lifecycle §1.2 (login / authorization / verification three axes)
        assert!(kinds.contains(&"cx.session.grant"));
        assert!(kinds.contains(&"cx.device.authorized"));
        assert!(kinds.contains(&"cx.device.revoked"));
        // device-lifecycle §7-§9 (verification ceremony events; replaces
        // legacy single `cx.device.cross_sign` placeholder).
        assert!(kinds.contains(&"cx.key.verification.start"));
        assert!(kinds.contains(&"cx.key.verification.done"));
        // discovery/read-receipts §6 — read marker is a wire event,
        // notification is *not* (it's a derived projection).
        assert!(kinds.contains(&"cx.read.marker"));
        assert!(kinds.contains(&"cx.receipt.read"));
        assert!(!kinds.contains(&"cx.notification.dismiss"));
        // audited-e2ee — attested + disclosed audit profiles
        assert!(kinds.contains(&"cx.audit.accessed"));
        assert!(kinds.contains(&"cx.audit.ryw_receipt"));
        // Removed in spec Round 7 / batch 1
        assert!(!kinds.contains(&"cx.flow.convert"));
        assert!(!kinds.contains(&"cx.mls.epoch"));
        // Renamed: cx.actor.profile.update -> cx.profile.update
        assert!(kinds.contains(&"cx.profile.update"));
        assert!(!kinds.contains(&"cx.actor.profile.update"));
    }

    #[test]
    fn known_event_kinds_have_protocol_namespace() {
        for kind in known_event_kinds() {
            assert!(
                kind.starts_with("cx."),
                "event kind `{kind}` 必须使用 cx.* 命名空间"
            );
            assert!(
                !kind.contains(' '),
                "event kind `{kind}` 不应包含空格"
            );
        }
    }

    /// Lock-down: registry counts at the time of last alignment.
    ///
    /// Spec `artifacts/registry/event-kind-registry.json` (commit fc7da5b)
    /// declares 109 active event kinds. Bumping yougen above this floor is
    /// fine; dropping below means we silently lost alignment with a spec
    /// upgrade (an upstream rename or addition that yougen forgot to land).
    ///
    /// When the spec adds new kinds, raise this lower bound. When yougen
    /// intentionally retires legacy kinds (after a deprecation window), keep
    /// the bound monotonic — never below 109 without an explicit decision.
    #[test]
    fn known_event_kinds_meet_registry_floor() {
        let kinds = known_event_kinds();
        assert!(
            kinds.len() >= 109,
            "yougen surfaces {} event kinds; spec registry fc7da5b declares 109 active. Drop below this floor only after deliberately retiring a legacy kind.",
            kinds.len()
        );
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
    /// All canonical event kinds follow the segment pattern `cx.<group>.<verb>[.<sub>]…`
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
}
