//! Conformance profiles, JSON schema validation, and security checks
//! per contrix-spec sections 12–13.

use contrix_sdk::Discoverability;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{ServerDescription, ServerDescriptionExt};

pub const PROFILE_MINIMAL_CLIENT: &str = "cx.profile.minimal_client.v1";
// T2.3: chat_only_client / kanban_only_client profile ids were removed from
// the spec (artifacts/registry/deprecated-profile-ids.json, since 0a5ab85).
// Replacement profile ids are cx.profile.chat_mvp.v1 / cx.profile.kanban_mvp.v1;
// modality is otherwise expressed via Space schema, not via single-modality
// profile gating.
pub const PROFILE_CHAT_MVP: &str = "cx.profile.chat_mvp.v1";
pub const PROFILE_KANBAN_MVP: &str = "cx.profile.kanban_mvp.v1";
pub const PROFILE_FULL_CLIENT: &str = "cx.profile.full_client.v1";
pub const PROFILE_E2EE_CLIENT: &str = "cx.profile.e2ee_client.v1";
pub const PROFILE_FEDERATION_MINIMAL: &str = "cx.profile.federation_minimal.v1";
// T0.3: push_gateway is a gateway role profile (not a client role). yougen
// is a client and MUST NOT declare itself as supporting the push_gateway
// profile (no entry in client_profile_declarations()). The constant is kept
// only so the settings panel can read whether the *server* advertises a
// push gateway endpoint.
pub const PROFILE_PUSH_GATEWAY: &str = "cx.profile.push_gateway.v1";
/// MLS Governance Binding hardening profile (`encryption-and-audit.md` §10).
///
/// Yougen ships the canonical `governance_binding` payload (see
/// [`crate::mls::governance::GovernanceBindingPayload`]) and the
/// `covered_frontier_cell` add-effect through [`contrix_sdk::mls_move`]. The
/// commit submit path remains gated on server features advertised via
/// [`crate::api::Api::events_describe`] before the profile reports `ready`.
pub const PROFILE_MLS_GOVERNANCE_BINDING_FULL: &str = "cx.profile.mls_governance_binding.full.v1";

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

/// Conformance tier per `artifacts/profiles/conformance-profiles.json` `profile_tiers`.
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
            profile_id: PROFILE_CHAT_MVP,
            label: "chat_mvp",
            description: "Chat MVP client: channels, timeline, message send/edit/redaction, reactions, and read markers.",
            local_supported: true,
            degradation_path: "Timeline can remain visible, but chat write controls stay gated.",
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
            description: "Full client: setup workflows, space lifecycle, audit, notifications, app views, and admin surfaces.",
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
            description: "MLS Governance Binding hardening: governance_binding payload + covered_frontier_cell add-effect on every commit.",
            local_supported: true,
            degradation_path: "Fall back to baseline e2ee_client without binding governance anchors to MLS commits.",
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
/// This list is used by:
/// - The explanatory panels in `views/audit.rs` / `views/space_admin.rs`.
/// - Cross-references in `claude-design/` and `_todos.md`.
/// - Fixture anchors for upcoming `tests/` end-to-end flows.
///
/// Spec sources: `overview/current-model.md`, `models/object-model-core.md`,
/// `models/object-model-standard.md` §5 (Flow / Message / edit and redact),
/// `crypto-media/device-lifecycle.md`, `authz/capabilities.md`,
/// `sync/operations-sync.md`, `crypto-media/encryption-and-audit.md`,
/// `crypto-media/audited-e2ee.md` (attested / disclosed audit profile),
/// `crypto-media/webrtc-signaling.md`, `extensions/applet-integration.md`,
/// `extensions/agent-protocol-interop.md`, `extensions/mimi-interop.md`.
/// Canonical registry: `artifacts/registry/event-kind-registry.json`.
pub fn known_event_kinds() -> Vec<&'static str> {
    // 110 active wire event kinds, mirrored from
    // `artifacts/registry/event-kind-registry.json` (active set, 2026-05-07).
    // ORDER MATTERS for diff-friendly maintenance: keep alphabetical inside each
    // group. When the spec adds/removes a kind, refresh
    // `tests/fixtures/event-kind-registry.snapshot.txt` via
    // `scripts/sync-event-kind-registry.ps1`, update this list, and bump the
    // count assertions in `mod tests` below.
    vec![
        // Account / actor profile
        "cx.account.blocklist",
        "cx.account.status",
        "cx.account_data.set",
        "cx.profile.create",
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
        // Range-completeness attestation (sync/operations-sync §4.2 + new in C45).
        // Non-reducer; used by audit layer to assert no silent omission within a
        // declared (from_frontier, to_frontier) interval.
        "cx.attestation.range_completeness",
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
        "cx.device.authorize",
        "cx.device.list_update",
        "cx.device.revoke",
        // Identity (DID proof + progressive disclosure §16 + C45 accountability grant)
        "cx.did.proof",
        // Round C45: issuer-signed endorsement that a subject DID is
        // accountable_to the issuer; required to verify
        // `Actor Profile.accountable_to[]`. See zh/models/actor.md §3.3.1.
        "cx.identity.accountability_grant",
        "cx.identity.disclosure_policy",
        "cx.identity.disclosure_receipt",
        "cx.identity.presentation_request",
        "cx.identity.presentation_response",
        // Flow / track (current-model §3-§4)
        "cx.flow.archive",
        "cx.flow.create",
        "cx.flow.move",
        "cx.flow.reorder",
        "cx.flow.restore",
        // Per contrix-spec dc01ad7 the four
        // `cx.flow.track.{enable,disable,update,set_primary}`
        // events were unified into a single `cx.flow.tracks.update`
        // carrying a `cx.patch.v1` JSON Patch against `Flow.tracks`.
        "cx.flow.tracks.update",
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
        "cx.moderation.franking_proof",
        "cx.moderation.report",
        // Morph (C45 — schema_migrate is the first-class schema_refs[]
        // evolution event with explicit compatibility_class; replaces ad-hoc
        // schema_refs[] writes via cx.morph.update).
        "cx.morph.archive",
        "cx.morph.create",
        "cx.morph.restore",
        "cx.morph.schema_migrate",
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
        // Read receipts / markers (discovery/read-receipts §6); notification
        // itself is a derived projection, not a canonical event.
        "cx.read_cursor.advance",
        "cx.receipt.read",
        // Redaction (cross-object — separate from cx.message.redact)
        "cx.redaction",
        // Relation
        "cx.relation.create",
        "cx.relation.tombstone",
        "cx.relation.update",
        // Schema evolution
        "cx.schema.define",
        "cx.schema.update",
        // Session grant (device-lifecycle §1.2)
        "cx.session.grant",
        // Sovereign deployment (sync/sovereign-deployment)
        "cx.sovereign.did_policy",
        // Realm (security boundary) — R1.7 inversion renamed the former
        // `cx.space.*` security events to `cx.realm.*` and freed the
        // `cx.space.*` namespace for the container lifecycle below.
        // T2.3 history: cx.space.lifecycle.set / cx.space.policy.set were
        // removed by spec 0a5ab85 — they have no realm successor.
        "cx.realm.child",
        "cx.realm.create",
        "cx.realm.organization",
        "cx.realm.parent",
        "cx.realm.update",
        "cx.realm.upgrade",
        // Space (navigation container, post-R1.7) — former `cx.place.*`
        // verbs over Board / List / Section containers.
        "cx.space.archive",
        "cx.space.create",
        "cx.space.restore",
        "cx.space.tombstone",
        "cx.space.update",
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

/// `wire_scope` classification for canonical event kinds — mirrors
/// `wire_scope_definitions` in `event-kind-registry.json`.
///
/// - `Durable` — written into Space history; reducer input.
/// - `ActorPrivate` — actor-scoped; reducer input but not shared into the Space.
/// - `Ephemeral` — short-TTL signaling; reducer MUST NOT use as state input.
///
/// The chat / call / verification views use this to keep ephemeral signals
/// from being rendered as durable history. The diff test in `mod tests`
/// pins the classification to `tests/fixtures/event-kind-wire-scopes.snapshot.tsv`,
/// which is regenerated from contrix-spec via
/// `scripts/sync-event-kind-registry.ps1`.
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

/// Event kinds whose wire_scope is `actor_private_event`.
const ACTOR_PRIVATE_EVENT_KINDS: &[&str] = &[
    "cx.account.blocklist",
    "cx.account_data.set",
    "cx.read_cursor.advance",
];

/// Event kinds whose wire_scope is `ephemeral_event`. Reducers must NOT take
/// these as state input — they are short-TTL signaling only.
const EPHEMERAL_EVENT_KINDS: &[&str] = &[
    "cx.call.signal",
    "cx.key.verification.accept",
    "cx.key.verification.cancel",
    "cx.key.verification.done",
    "cx.key.verification.key",
    "cx.key.verification.mac",
    "cx.key.verification.ready",
    "cx.key.verification.request",
    "cx.key.verification.start",
    "cx.presence",
    "cx.receipt.read",
    "cx.typing",
];

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
    if ACTOR_PRIVATE_EVENT_KINDS.contains(&event_kind) {
        return Some(EventKindWireScope::ActorPrivate);
    }
    if EPHEMERAL_EVENT_KINDS.contains(&event_kind) {
        return Some(EventKindWireScope::Ephemeral);
    }
    if known_event_kinds().contains(&event_kind) {
        return Some(EventKindWireScope::Durable);
    }
    None
}

/// All event kinds yougen currently classifies as ephemeral signaling. The
/// chat/call views use this to render their "ephemeral signals" banners
/// programmatically rather than re-typing kind literals.
pub fn ephemeral_event_kinds() -> &'static [&'static str] {
    EPHEMERAL_EVENT_KINDS
}

/// All event kinds yougen currently classifies as actor-private.
pub fn actor_private_event_kinds() -> &'static [&'static str] {
    ACTOR_PRIVATE_EVENT_KINDS
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
/// `contrix-spec/artifacts/profiles/`) against what the server
/// advertises in `supported_operations`. Profiles unknown to the SDK
/// table return a single sentinel so the UI surfaces "this profile id
/// isn't in the spec" rather than silently passing.
///
/// `required_event_kinds` / `required_schemas` are intentionally NOT
/// checked here — those describe what the *client* must implement,
/// not what the server has to expose. The server-side gate is about
/// "can I call the endpoints I'd need" only.
fn missing_requirements(profile_id: &str, server: &ServerDescription) -> Vec<String> {
    let Some(req) = contrix_sdk::generated::profile_requirements::requirements_for(profile_id)
    else {
        return vec![format!("unknown profile {profile_id}")];
    };
    req.required_operations
        .iter()
        .filter(|operation| !server.supports_operation(operation))
        .map(|operation| (*operation).to_owned())
        .collect()
}

#[allow(dead_code)]
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
    // F-PROFILE-1: enforce the conformance profile by rejecting any
    // `type` (canonical event kind) outside `known_event_kinds()`.
    // The schema-level shape check above already guarantees `type` is
    // present; here we ensure it's also a kind yougen is qualified
    // to apply.
    if let Some(kind) = obj.get("type").and_then(|v| v.as_str()) {
        require_known_event_kind(kind)?;
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
    InvalidValue {
        field: String,
        expected: String,
    },
    /// F-PROFILE-1: the event's `type` is not in the conformance profile
    /// yougen advertises (see [`known_event_kinds`]). Surfaces as a
    /// rejection at event ingest so a profile-drift attack / spec bump
    /// can't smuggle an unknown reducer kind into local state.
    UnknownEventKind(String),
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
            Self::UnknownEventKind(kind) => {
                write!(
                    f,
                    "event kind `{kind}` is outside yougen's conformance profile"
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

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
                .any(|p| p.profile_id == "cx.profile.chat_mvp.v1" && p.supported)
        );
        // T0.3: yougen is a client, push_gateway is a gateway role — it
        // MUST NOT appear in the client's supported profile set.
        assert!(
            !profiles
                .iter()
                .any(|p| p.profile_id == "cx.profile.push_gateway.v1")
        );
        // T2.3: the legacy single-modality profile ids are hard_reject per
        // artifacts/registry/deprecated-profile-ids.json; they MUST NOT
        // appear in yougen's declared profile set.
        assert!(
            !profiles
                .iter()
                .any(|p| p.profile_id == "cx.profile.chat_only_client.v1")
        );
        assert!(
            !profiles
                .iter()
                .any(|p| p.profile_id == "cx.profile.kanban_only_client.v1")
        );
    }

    #[test]
    fn profile_readiness_reports_server_gaps() {
        // Server advertises exactly the operations SDK's
        // `requirements_for(PROFILE_MINIMAL_CLIENT)` requires — minimal
        // client should be ready. `chat_mvp` additionally requires
        // `cx.account.subscribe` which the fixture intentionally omits, so
        // the readiness gate flags it as missing.
        let server: ServerDescription = serde_json::from_value(json!({
            "service_did": "did:web:server.example",
            "trust_domain": "cx:trust_domain:server.example",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [PROFILE_MINIMAL_CLIENT],
            "supported_features": [],
            "supported_operations": [
                "cx.events.get",
                "cx.events.query",
                "cx.server.describe",
            ],
            "supported_bindings": [],
            "auth_metadata": {},
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
                .any(|missing| missing.contains("cx.account.subscribe")),
            "expected chat_mvp to flag missing cx.account.subscribe, got {:?}",
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
            "operation_id": "op1",
            "space_id": "cx:space:s1",
            "actor": "did:web:alice",
            "type": "cx.message.create",
            "causal": {"hlc": "0000018ef01234-0001-deadbeef", "actor_seq": 1}
        });
        assert!(validate_structure(&event, "event").is_ok());
    }

    /// F-PROFILE-1: an otherwise well-formed event whose `type` falls
    /// outside `known_event_kinds()` must be rejected at the validate
    /// boundary instead of being treated as a "default" branch later.
    #[test]
    fn validate_event_schema_rejects_unknown_kind() {
        let event = json!({
            "operation_id": "op1",
            "space_id": "cx:space:s1",
            "actor": "did:web:alice",
            "type": "cx.bogus.kind",
            "causal": {"hlc": "0000018ef01234-0001-deadbeef", "actor_seq": 1}
        });
        match validate_structure(&event, "event") {
            Err(ValidationError::UnknownEventKind(kind)) => {
                assert_eq!(kind, "cx.bogus.kind");
            }
            other => panic!("expected UnknownEventKind, got {other:?}"),
        }
    }

    #[test]
    fn require_known_event_kind_accepts_canonical_and_rejects_garbage() {
        assert!(require_known_event_kind("cx.message.create").is_ok());
        assert!(require_known_event_kind("cx.flow.update").is_ok());
        assert!(require_known_event_kind("cx.typing").is_ok());
        let err = require_known_event_kind("cx.bogus.kind").expect_err("unknown kind must error");
        assert!(matches!(err, ValidationError::UnknownEventKind(_)));
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
        // C18 wire-break (spec 2026-05-08): cx.flow.branch.* (7 kinds) renamed
        // and pruned to cx.flow.track.{enable,disable,update,set_primary}
        // (4 kinds; spec dropped member/history_visibility/policy_components
        // because tracks no longer carry independent membership/visibility/
        // policy — see Flow.discussion_realm_ref). Net -3 from prior 110.
        // Follow-on wire-break (spec dc01ad7, 2026-05-18): the four track
        // events above unified into a single `cx.flow.tracks.update` carrying
        // a `cx.patch.v1` JSON Patch against `Flow.tracks`. Net -3 more.
        // Round C45 (spec 5ed365c, 2026-05-18 main): +3 new event kinds
        // (cx.attestation.range_completeness / cx.identity.accountability_grant /
        // cx.morph.schema_migrate). The two `.v1`-suffixed audit kinds were
        // renamed in-place (cx.audit.epoch_key_destruction[.v1] and
        // cx.realm.audit_policy_downgrade[.v1] — yougen does not yet surface
        // those typed kinds, so the rename doesn't shift the count).
        // Spec `artifacts/registry/event-kind-registry.json` itself declares
        // 134 active event kinds at HEAD — yougen's `known_event_kinds()`
        // surface remains a subset (105 here).
        // T2.3 wire-break: cx.space.lifecycle.set and cx.space.policy.set
        // were removed (artifacts/registry/removed-event-kinds.json,
        // hard_reject); net -2 from prior 107.
        // R1.7 realm/space inversion: 6 former `cx.space.*` security events
        // were renamed to `cx.realm.*`, and 5 new `cx.space.*` container
        // lifecycle kinds (archive/create/restore/tombstone/update) were
        // added — net +5 from prior 105.
        assert_eq!(known_event_kinds().len(), 110);
    }

    #[test]
    fn known_event_kinds_covers_load_bearing_kinds() {
        let kinds = known_event_kinds();
        // current-model §3 — unified track update (spec dc01ad7)
        assert!(kinds.contains(&"cx.flow.tracks.update"));
        // Legacy split events removed in the dc01ad7 unification.
        assert!(!kinds.contains(&"cx.flow.track.enable"));
        assert!(!kinds.contains(&"cx.flow.track.disable"));
        assert!(!kinds.contains(&"cx.flow.track.update"));
        assert!(!kinds.contains(&"cx.flow.track.set_primary"));
        // current-model §4 — board / list workflow container
        assert!(kinds.contains(&"cx.flow.move"));
        assert!(kinds.contains(&"cx.flow.reorder"));
        // device-lifecycle §1.2 (login / authorization / verification three axes)
        assert!(kinds.contains(&"cx.session.grant"));
        assert!(kinds.contains(&"cx.device.authorize"));
        assert!(kinds.contains(&"cx.device.revoke"));
        // device-lifecycle §7-§9 verification ceremony events.
        assert!(kinds.contains(&"cx.key.verification.start"));
        assert!(kinds.contains(&"cx.key.verification.done"));
        // discovery/read-receipts §6 — read marker is a wire event,
        // notification is *not* (it's a derived projection).
        assert!(kinds.contains(&"cx.read_cursor.advance"));
        assert!(kinds.contains(&"cx.receipt.read"));
        assert!(!kinds.contains(&"cx.notification.dismiss"));
        // audited-e2ee — attested + disclosed audit profiles
        assert!(kinds.contains(&"cx.audit.accessed"));
        assert!(kinds.contains(&"cx.audit.ryw_receipt"));
        // Removed by spec
        assert!(!kinds.contains(&"cx.flow.convert"));
        assert!(!kinds.contains(&"cx.mls.epoch"));
        // T2.3 (spec 0a5ab85): single 'set' kinds were decomposed into
        // per-component cells / typed lifecycle events.
        assert!(!kinds.contains(&"cx.space.lifecycle.set"));
        assert!(!kinds.contains(&"cx.space.policy.set"));
        // R1.7 realm/space inversion: security-boundary events live in
        // cx.realm.*; container lifecycle events live in cx.space.*.
        assert!(kinds.contains(&"cx.realm.create"));
        assert!(kinds.contains(&"cx.realm.update"));
        assert!(kinds.contains(&"cx.realm.child"));
        assert!(kinds.contains(&"cx.realm.parent"));
        assert!(kinds.contains(&"cx.space.archive"));
        assert!(kinds.contains(&"cx.space.restore"));
        assert!(kinds.contains(&"cx.space.tombstone"));
        // Renamed: cx.actor.profile.update -> cx.profile.update
        assert!(kinds.contains(&"cx.profile.update"));
        assert!(!kinds.contains(&"cx.actor.profile.update"));
    }

    #[test]
    fn known_event_kinds_have_protocol_namespace() {
        for kind in known_event_kinds() {
            assert!(
                kind.starts_with("cx."),
                "event kind `{kind}` must live in the cx.* namespace"
            );
            assert!(
                !kind.contains(' '),
                "event kind `{kind}` must not contain spaces"
            );
        }
    }

    /// Lock-down: registry counts at the time of last alignment.
    ///
    /// C18 wire-break (spec 2026-05-08) deliberately retired
    /// `cx.flow.branch.{member,history_visibility,policy_components}` — three
    /// events that had no track-namespace successor — so the prior floor of
    /// 110 is no longer meaningful. Spec dc01ad7 (2026-05-18) then unified
    /// the four `cx.flow.track.{enable,disable,update,set_primary}` events
    /// into a single `cx.flow.tracks.update`, dropping three more entries.
    /// We pin to 102 to track the post-T2.3 count. The spec itself
    /// declares 131 active kinds at HEAD; yougen surfaces the typed subset
    /// relevant to its UI flows. T2.3 dropped cx.space.lifecycle.set and
    /// cx.space.policy.set (-2 from the prior 104 floor).
    #[test]
    fn known_event_kinds_meet_registry_floor() {
        let kinds = known_event_kinds();
        // R1.7 realm/space inversion raised the floor from 102 to 107:
        // the 6 renamed `cx.space.*` → `cx.realm.*` are net-zero, and the
        // 5 new container lifecycle kinds add a stable floor of 107.
        assert!(
            kinds.len() >= 107,
            "yougen surfaces {} event kinds; floor 107 set after R1.7 added cx.space.{{archive,create,restore,tombstone,update}} on top of the realm/space inversion.",
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

    /// Hermetic diff against the vendored snapshot of
    /// `contrix-spec/spec/v1/artifacts/registry/event-kind-registry.json`.
    ///
    /// The snapshot lives in `tests/fixtures/event-kind-registry.snapshot.txt`
    /// and is refreshed via `scripts/sync-event-kind-registry.ps1`. When the
    /// spec adds or renames an event kind, the script regenerates the snapshot
    /// (which makes this test fail until `known_event_kinds()` is updated to
    /// match), so spec drift never lands silently. The snapshot is the
    /// authoritative reference inside the yougen tree — there is intentionally
    /// no runtime fetch of contrix-spec.
    const EVENT_KIND_REGISTRY_SNAPSHOT: &str =
        include_str!("../tests/fixtures/event-kind-registry.snapshot.txt");

    fn parse_snapshot_kinds(snapshot: &str) -> Vec<String> {
        snapshot
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn known_event_kinds_match_spec_snapshot() {
        let snapshot: std::collections::BTreeSet<String> =
            parse_snapshot_kinds(EVENT_KIND_REGISTRY_SNAPSHOT)
                .into_iter()
                .collect();
        let yougen: std::collections::BTreeSet<String> =
            known_event_kinds().into_iter().map(str::to_owned).collect();

        let missing: Vec<&String> = snapshot.difference(&yougen).collect();
        let extra: Vec<&String> = yougen.difference(&snapshot).collect();

        assert!(
            missing.is_empty() && extra.is_empty(),
            "yougen `known_event_kinds()` is out of sync with `tests/fixtures/event-kind-registry.snapshot.txt`. \
             Refresh the snapshot via `scripts/sync-event-kind-registry.ps1` and reconcile both files in the same commit. \
             missing_in_yougen={missing:?} extra_in_yougen={extra:?}"
        );
    }

    /// Hermetic diff between the typed `event_kind_wire_scope()` classifier
    /// and the vendored registry snapshot. Catches drift in *either* direction:
    ///   1. spec moves a kind between scopes (e.g. ephemeral → durable)
    ///   2. yougen forgets to update the in-code classifier alongside the spec
    ///   3. a kind exists in one source but not the other
    ///
    /// Refresh `tests/fixtures/event-kind-wire-scopes.snapshot.tsv` via
    /// `scripts/sync-event-kind-registry.ps1` and reconcile the in-code lists
    /// (`ACTOR_PRIVATE_EVENT_KINDS`, `EPHEMERAL_EVENT_KINDS`) in the same commit.
    const EVENT_KIND_WIRE_SCOPE_SNAPSHOT: &str =
        include_str!("../tests/fixtures/event-kind-wire-scopes.snapshot.tsv");

    fn parse_wire_scope_snapshot(snapshot: &str) -> Vec<(String, super::EventKindWireScope)> {
        snapshot
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let mut parts = line.splitn(2, '\t');
                let kind = parts.next().expect("snapshot row missing kind").to_owned();
                let scope_str = parts.next().expect("snapshot row missing scope");
                let scope = super::EventKindWireScope::from_registry_str(scope_str)
                    .unwrap_or_else(|| panic!("unknown wire_scope `{scope_str}` in snapshot"));
                (kind, scope)
            })
            .collect()
    }

    #[test]
    fn event_kind_wire_scope_classifier_matches_snapshot() {
        let snapshot = parse_wire_scope_snapshot(EVENT_KIND_WIRE_SCOPE_SNAPSHOT);

        let mut mismatches: Vec<String> = Vec::new();
        for (kind, expected) in &snapshot {
            match super::event_kind_wire_scope(kind) {
                Some(actual) if actual == *expected => {}
                Some(actual) => mismatches.push(format!(
                    "{kind}: snapshot={} but classifier={}",
                    expected.as_registry_str(),
                    actual.as_registry_str()
                )),
                None => mismatches.push(format!(
                    "{kind}: snapshot={} but classifier returned None",
                    expected.as_registry_str()
                )),
            }
        }

        let snapshot_kinds: std::collections::BTreeSet<String> =
            snapshot.iter().map(|(k, _)| k.clone()).collect();
        for kind in known_event_kinds() {
            if !snapshot_kinds.contains(kind) {
                mismatches.push(format!(
                    "{kind}: in known_event_kinds but absent from snapshot"
                ));
            }
        }

        assert!(
            mismatches.is_empty(),
            "event_kind_wire_scope classifier is out of sync with the snapshot. \
             Refresh via `scripts/sync-event-kind-registry.ps1` and reconcile the \
             in-code `ACTOR_PRIVATE_EVENT_KINDS` / `EPHEMERAL_EVENT_KINDS` constants. \
             mismatches=\n - {}",
            mismatches.join("\n - "),
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
        assert_eq!(super::event_kind_wire_scope("cx.bogus.kind"), None);
    }

    #[test]
    fn event_kind_registry_snapshot_is_well_formed() {
        let kinds = parse_snapshot_kinds(EVENT_KIND_REGISTRY_SNAPSHOT);
        assert!(
            !kinds.is_empty(),
            "snapshot must list at least one event kind"
        );

        let mut seen = std::collections::BTreeSet::new();
        for kind in &kinds {
            assert!(
                kind.starts_with("cx."),
                "snapshot entry `{kind}` missing cx.* namespace"
            );
            assert!(
                seen.insert(kind.clone()),
                "snapshot contains duplicate entry `{kind}`"
            );
            for ch in kind.chars() {
                assert!(
                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_',
                    "snapshot entry `{kind}` has illegal char `{ch}`"
                );
            }
        }

        let mut sorted = kinds.clone();
        sorted.sort();
        assert_eq!(
            sorted, kinds,
            "snapshot entries must stay sorted to keep diffs reviewable"
        );
    }
}
