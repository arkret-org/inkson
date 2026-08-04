#![cfg(not(target_arch = "wasm32"))]

//! Conformance gate: every typed builder in inkson MUST produce an
//! Event that validates against arkret-spec event-envelope.schema.json.
//!
//! Stream J of `_claude_todos.md`: for each typed builder in
//! `inkson::event_builders`,
//! run build, stamp the wire-only fields a real submitter would attach
//! (`seal_basis` when the kind is a Control Move, `proofs[0]` from a real
//! Ed25519 signer), serialise, and validate
//! against `arkret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`.
//! Schema distinguishes Control Moves, DataEvents, and a few bootstrap/facet
//! reducer kinds; the gate therefore covers both the builder output and the
//! sign-and-stamp pipeline immediately downstream.

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use inkson::event_builders;
use inkson::operation::{Event, EventExt, EventKind};
use jsonschema::{Registry, Resource};
use serde_json::Value;

// ----------------------------------------------------------------------
// Shared path / file helpers
// ----------------------------------------------------------------------

fn spec_artifact(path: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("inkson lives next to arkret-spec")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join(path)
}

#[test]
fn realm_event_paths_do_not_fall_back_to_default_sha256_helpers() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut pending = vec![manifest.join("src")];
    let forbidden = [
        "arkret_sdk::signatures::sign_event(",
        "arkret_signatures::sign_event(",
        "arkret_sdk::event_proof_verification_context(",
    ];
    let mut violations = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        {
            let path = entry.expect("read source entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            for needle in forbidden {
                if source.contains(needle) {
                    violations.push(format!("{} contains {needle}", path.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Realm signing and verification must use a trusted explicit digest suite:\n{}",
        violations.join("\n")
    );
}

// ----------------------------------------------------------------------
// J1 — Event-schema validation gate
// ----------------------------------------------------------------------

/// Every `spec/v1/artifacts/schemas/*.json` resource, registered under its
/// `$id` plus the relative aliases the spec files `$ref` each other by.
/// Compiled once per test process and shared by every validator below.
fn spec_schema_registry() -> &'static Registry<'static> {
    static REGISTRY: OnceLock<Registry<'static>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let schemas_dir = spec_artifact("schemas");
        let mut registry = Registry::new();
        for entry in fs::read_dir(&schemas_dir).unwrap_or_else(|err| {
            panic!("read schemas dir {} failed: {err}", schemas_dir.display());
        }) {
            let path = entry.expect("schema dir entry").path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let raw = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {} failed: {err}", path.display()));
            let schema: Value = serde_json::from_str(&raw)
                .unwrap_or_else(|err| panic!("{} parses as JSON: {err}", path.display()));
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("schema filename is UTF-8")
                .to_owned();
            if let Some(id) = schema.get("$id").and_then(Value::as_str) {
                registry = registry
                    .add(id, Resource::from_contents(schema.clone()))
                    .unwrap_or_else(|err| panic!("register schema id {id}: {err}"));
            }
            for alias in [
                filename.clone(),
                format!("./{filename}"),
                format!("schemas/{filename}"),
            ] {
                registry = registry
                    .add(alias.as_str(), Resource::from_contents(schema.clone()))
                    .unwrap_or_else(|err| panic!("register schema alias {alias}: {err}"));
            }
        }
        registry.prepare().expect("schema registry prepares")
    })
}

/// Read one spec schema file and return its `$id`.
fn spec_schema_id(filename: &str) -> String {
    let path = spec_artifact(&format!("schemas/{filename}"));
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {} failed: {err}", path.display()));
    let schema: Value =
        serde_json::from_str(&raw).unwrap_or_else(|err| panic!("{filename} parses as JSON: {err}"));
    schema
        .get("$id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{filename} declares no $id"))
        .to_owned()
}

/// Compile the event-schema once per test process.
fn event_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let event_schema_path = spec_artifact("schemas/event-envelope.schema.json");
        let event_schema_raw = fs::read_to_string(&event_schema_path).unwrap_or_else(|err| {
            panic!("read {} failed: {err}", event_schema_path.display());
        });
        let event_schema: Value = serde_json::from_str(&event_schema_raw)
            .expect("event-envelope.schema.json parses as JSON");
        let event_schema_id = event_schema
            .get("$id")
            .and_then(Value::as_str)
            .unwrap_or("https://arkret.org/v1/schemas/event-envelope.schema.json")
            .to_owned();

        jsonschema::options()
            .with_registry(spec_schema_registry())
            .with_base_uri(event_schema_id.as_str())
            .build(&event_schema)
            .expect("event-schema compiles")
    })
}

/// Validate a value against one `event-payload.schema.json#/$defs/<def_name>`.
///
/// Used where the *payload* has a dedicated closed def that the envelope
/// schema's per-kind `allOf` does not point at; validating the envelope alone
/// would then silently skip the closed check.
fn assert_matches_payload_def(label: &str, def_name: &str, value: &Value) {
    let reference = Value::String(format!(
        "{}#/$defs/{def_name}",
        spec_schema_id("event-payload.schema.json")
    ));
    let schema = Value::Object([("$ref".to_owned(), reference)].into_iter().collect());
    let validator = jsonschema::options()
        .with_registry(spec_schema_registry())
        .build(&schema)
        .unwrap_or_else(|err| panic!("{def_name} compiles: {err}"));
    if !validator.is_valid(value) {
        let errors: Vec<String> = validator
            .iter_errors(value)
            .map(|err| format!("  - {} (at {})", err, err.instance_path()))
            .collect();
        panic!(
            "{label}: value failed {def_name} validation:\n{}\nvalue was:\n{}",
            errors.join("\n"),
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    }
}

/// Validate a value against a whole spec schema file, or against one `$defs`
/// entry inside it when `def_name` is set.
///
/// The payload-def helper above is hard-wired to `event-payload.schema.json`;
/// device messages and service DTOs live in their own files.
fn assert_matches_schema(label: &str, filename: &str, def_name: Option<&str>, value: &Value) {
    let reference = match def_name {
        Some(def_name) => format!("{}#/$defs/{def_name}", spec_schema_id(filename)),
        None => spec_schema_id(filename),
    };
    let schema = Value::Object(
        [("$ref".to_owned(), Value::String(reference.clone()))]
            .into_iter()
            .collect(),
    );
    let validator = jsonschema::options()
        .with_registry(spec_schema_registry())
        .build(&schema)
        .unwrap_or_else(|err| panic!("{reference} compiles: {err}"));
    if !validator.is_valid(value) {
        let errors: Vec<String> = validator
            .iter_errors(value)
            .map(|err| format!("  - {} (at {})", err, err.instance_path()))
            .collect();
        panic!(
            "{label}: value failed {reference} validation:\n{}\nvalue was:\n{}",
            errors.join("\n"),
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    }
}

/// Deterministic Ed25519 key the test process uses for signing
/// envelopes. The seed is fixed so reruns are byte-identical; in
/// production this is loaded from the OS keychain.
fn test_signing_key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| {
        SigningKey::from_bytes(&[
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42,
        ])
    })
}

const TEST_REALM_ID: &str = "ak:realm:0196419b-0000-7000-8000-000000000001";
const TEST_SPACE_ID: &str = "ak:space:0196419b-0000-7000-8000-000000000002";
const TEST_ACTOR_ID: &str = "did:web:alice.example";
const TEST_SERVICE_ID: &str = "did:web:server.example";
const TEST_INVITEE_DID: &str = "did:web:bob.example";
const TEST_ANCHOR_REF: &str =
    "ak:seal:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_ROOT_HASH: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Stamp the wire fields the submit pipeline would normally attach
/// (CBA basis + Ed25519 proof) so the envelope satisfies the reducer-input
/// rules baked into event-envelope.schema.json.
fn stamp_wire_fields(envelope: &mut Event) {
    match reducer_input_plane(envelope) {
        // Control Move: `seal_basis` and nothing from the data-plane pair.
        Some("control") if !cba_exempt_reducer_kind(&envelope.kind) => {
            if envelope.seal_basis.is_none() {
                envelope.seal_basis = Some(test_seal_basis());
            }
        }
        // DataEvent: the schema requires `seal_ref` AND `auth_context`
        // together, and forbids `seal_basis` alongside them. Both are attached
        // by the submit pipeline, not by the typed builder, so the gate has to
        // stamp them before validating what actually goes on the wire.
        Some("data") => {
            if envelope.seal_ref.is_none() {
                envelope.seal_ref = Some(
                    arkret_sdk::SealId::new(TEST_ANCHOR_REF.to_owned())
                        .expect("test seal id is canonical"),
                );
            }
            if envelope.auth_context.is_none() {
                envelope.auth_context = Some(test_auth_context());
            }
        }
        _ => {}
    }
    let signer_did = TEST_ACTOR_ID;
    let key_id = format!("{signer_did}#device");
    envelope
        .sign_ed25519(signer_did, key_id, test_signing_key())
        .expect("Ed25519 sign succeeds for schema-conformant envelope");
}

/// Whether a real submitter would attach `seal_basis` to this envelope.
///
/// The pre-v1 test read the producer-written `effects[]`. That channel is gone:
/// what an Event writes — and on which CBA plane — comes from the registered
/// contract, so the plane is read from the registry here exactly as
/// `arkret_schema::validate_registered_cell_writes_in_context` reads it at
/// admission. Guessing from the kind name would fork the rule.
fn reducer_input_plane(envelope: &Event) -> Option<&'static str> {
    envelope
        .kind
        .descriptor()
        .filter(|descriptor| descriptor.reducer_input)
        .and_then(|descriptor| descriptor.plane)
}

/// Kinds a real submitter builds WITHOUT `seal_basis` because they sit in the
/// Realm genesis batch, where no accepted Seal exists yet
/// (realm-and-space.md §2.5). Read from the shared SDK helper rather than a
/// local hand-list: a second copy of a closed protocol list is exactly the
/// drift that lets a bootstrap follow-up go untested.
fn cba_exempt_reducer_kind(kind: &EventKind) -> bool {
    kind == &EventKind::RealmCreate
        || arkret_policy::realm_bootstrap::is_realm_bootstrap_followup_kind(kind.as_str())
}

/// The `{did, key_id, key_epoch}` a DataEvent pins so the receiver knows which
/// signing key to verify authorization with at `seal_ref`. Effective
/// capabilities are still derived from the accepted basis; this only names the
/// key, it never selects a capability.
fn test_auth_context() -> arkret_sdk::AuthContext {
    arkret_sdk::AuthContext {
        did: arkret_sdk::Did::new(TEST_ACTOR_ID.to_owned()).expect("test actor DID is canonical"),
        // `key_id` is the bare verification-method fragment (the schema
        // pattern forbids `#`), which is what `data_event_key_id_for`
        // produces from the active signer's device id.
        key_id: "device".to_owned(),
        key_epoch: 0,
        credential_epoch: None,
    }
}

fn test_seal_basis() -> arkret_sdk::SealBasis {
    let view: arkret_sdk::RealmSealFrontierView = serde_json::from_value(serde_json::json!({
        "kind": "realm_seal",
        "realm_id": TEST_REALM_ID,
        "seal_id": TEST_ANCHOR_REF,
        "control_event_set_root": TEST_ROOT_HASH,
        "state_root": TEST_ROOT_HASH,
        "governance_health": {
            "status": "healthy",
            "pending_proposals": [],
            "retained_faults": []
        }
    }))
    .expect("test RealmSealFrontierView is valid");
    view.seal_basis()
}

/// Sanity check: the validator MUST reject obvious schema violations.
/// Catches a class of bug where the registry/base-URI wiring silently
/// degrades into a no-op (which would let every other test trivially
/// pass and miss real drift). Run alongside the live tests so any
/// future cleanup that breaks resolver wiring trips this immediately.
#[test]
fn schema_validator_rejects_obviously_invalid_envelope() {
    let validator = event_schema_validator();

    // Empty object — missing every required top-level field.
    assert!(
        !validator.is_valid(&serde_json::json!({})),
        "validator accepted an empty object; resolver wiring is broken"
    );

    // Correct shape but wrong event_id pattern (should reject — uuid7
    // pattern requires `7<...>` in time-hi field).
    let bogus = serde_json::json!({
        "event_id": "ak:event:not-a-uuid",
        "kind": "ak.realm.create",
        "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000001",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1,
        "created_at": "2026-05-21T13:00:00.000Z",
        "prev_refs": [],
        "refs": [],
        "payload": {},
        "proofs": []
    });
    assert!(
        !validator.is_valid(&bogus),
        "validator accepted a malformed event_id; resolver wiring is broken"
    );

    // Reducer-input kind missing preconditions/effects/seal_ref MUST
    // be rejected per the `then.required` rule on the reducer-kind
    // branch of the top-level `allOf`. If this slips through, the
    // schema validator is silently degraded to a syntax-only checker.
    let reducer_missing_required = serde_json::json!({
        "event_id": "ak:event:0196419b-0000-7777-8000-000000000003",
        "kind": "ak.realm.create",
        "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000001",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1,
        "created_at": "2026-05-21T13:00:00.000Z",
        "prev_refs": [],
        "refs": [],
        "payload": {},
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": "did:web:alice.example#device",
            "event_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "created_at": "2026-05-21T13:00:00.000Z",
            "jws": "a.b.c"
        }]
    });
    assert!(
        !validator.is_valid(&reducer_missing_required),
        "validator accepted a reducer-input ak.realm.create envelope \
         missing preconditions/effects/seal_ref; the conditional `if/then` \
         branch on event-envelope.schema.json is not being evaluated"
    );
}

/// Validate `envelope` against event-schema. Panics with a readable
/// diff on any schema violation.
fn assert_envelope_matches_schema(label: &str, envelope: &Event) {
    assert!(
        envelope
            .hlc
            .as_ref()
            .is_some_and(|hlc| !hlc.as_str().is_empty()),
        "{label}: builder produced empty hlc — should be `<12>-<4>-<8>` hex"
    );
    let value = serde_json::to_value(envelope)
        .unwrap_or_else(|err| panic!("{label}: serialize envelope: {err}"));
    let validator = event_schema_validator();
    if !validator.is_valid(&value) {
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|err| format!("  - {} (at {})", err, err.instance_path()))
            .collect();
        let pretty = serde_json::to_string_pretty(&value).unwrap_or_default();
        panic!(
            "{label}: envelope failed event-schema validation:\n{}\nenvelope was:\n{}",
            errors.join("\n"),
            pretty
        );
    }
}

#[test]
fn build_realm_create_event_matches_event_schema() {
    let mut envelope = event_builders::build_realm_create_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        TEST_SERVICE_ID,
        "Engineering",
        Some("Roadmap work"),
        "listed",
        "invite",
        "shared",
        "mls_rfc9420",
        "standard",
        "restricted",
        "single_did",
        "sha256",
        "ak:trust_domain:server.example",
        None,
    )
    .expect("build_realm_create_event succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_realm_create_event", &envelope);
}

#[test]
fn build_space_create_event_matches_event_schema() {
    let mut envelope = event_builders::build_space_create_event(
        TEST_SPACE_ID,
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        "Launch checklist",
        Some("Quarterly launch tracking"),
        "list",
        None,
        None,
    )
    .expect("build_space_create_event succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_space_create_event", &envelope);
}

#[test]
fn build_space_lifecycle_event_archive_matches_event_schema() {
    let mut envelope = event_builders::build_space_lifecycle_event(
        TEST_SPACE_ID,
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::SpaceArchive,
    )
    .expect("build_space_lifecycle_event(archive) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_space_lifecycle_event[archive]", &envelope);
}

#[test]
fn build_space_lifecycle_event_restore_matches_event_schema() {
    let mut envelope = event_builders::build_space_lifecycle_event(
        TEST_SPACE_ID,
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::SpaceRestore,
    )
    .expect("build_space_lifecycle_event(restore) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_space_lifecycle_event[restore]", &envelope);
}

#[test]
fn build_space_lifecycle_event_tombstone_matches_event_schema() {
    let mut envelope = event_builders::build_space_lifecycle_event(
        TEST_SPACE_ID,
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::SpaceTombstone,
    )
    .expect("build_space_lifecycle_event(tombstone) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_space_lifecycle_event[tombstone]", &envelope);
}

#[test]
fn build_realm_state_event_join_rule_matches_event_schema() {
    let mut envelope = event_builders::build_realm_state_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::RealmJoinRule,
        serde_json::json!("invite"),
    )
    .expect("build_realm_state_event(join_rule) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_realm_state_event[join_rule]", &envelope);
}

#[test]
fn build_realm_state_event_history_visibility_matches_event_schema() {
    let mut envelope = event_builders::build_realm_state_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::RealmHistoryVisibility,
        serde_json::json!("shared"),
    )
    .expect("build_realm_state_event(history_visibility) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_realm_state_event[history_visibility]", &envelope);
}

#[test]
fn build_realm_history_sharing_policy_event_matches_event_schema() {
    let mut envelope = event_builders::build_realm_history_sharing_policy_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        arkret_sdk::HistorySharingPolicyPayloadValue {
            version: 1,
            default_key_share: arkret_sdk::HistoryKeyShareDefault::EventTimeVisibility,
            pre_join_history: None,
            post_removal_recovery: None,
            allowed_key_sources: vec![arkret_sdk::HistoryKeySource::VerifiedMemberDevice],
            allowed_receiver_states: Some(vec![
                arkret_sdk::HistorySharingReceiverClass::ActiveMember,
            ]),
            audit: arkret_sdk::HistorySharingPolicyPayloadValueAudit {
                share_audit_event_required: true,
                access_audit_required: true,
            },
            restricted_rules: None,
        },
    )
    .expect("build_realm_history_sharing_policy_event succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_realm_state_event[history_sharing_policy]", &envelope);
}

#[test]
fn build_realm_preview_policy_event_matches_event_schema() {
    let mut envelope = event_builders::build_realm_state_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::RealmPreviewPolicy,
        serde_json::json!({
            "mode": "stripped_state",
            "audiences": ["link_token_holder"],
            "fields": ["title", "summary", "join_rule", "history_visibility"],
            "token": {
                "required": true,
                "ttl_seconds": 600,
                "bind_target_digest": true
            }
        }),
    )
    .expect("build_realm_state_event(preview_policy) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_realm_state_event[preview_policy]", &envelope);
}

#[test]
fn build_member_state_event_matches_event_schema() {
    // `build_member_state_event` itself is private. It is a thin wrapper
    // around `build_member_state_transition_event` with from=None and
    // reason="space_create" — same canonical shape. We exercise the
    // wrapper path indirectly via `build_realm_bootstrap_events` (which
    // calls it for each invitee) and pick out the member-state envelope.
    let events = event_builders::build_realm_bootstrap_events(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        TEST_SERVICE_ID,
        "Engineering",
        None,
        "listed",
        "invite",
        "shared",
        "mls_rfc9420",
        "standard",
        "restricted",
        "single_did",
        "sha256",
        "ak:trust_domain:server.example",
        &[TEST_INVITEE_DID.to_owned()],
        &[],
        None,
        None,
    )
    .expect("build_realm_bootstrap_events succeeds");
    let mut envelope = events
        .into_iter()
        .find(|event| event.kind == EventKind::MemberState)
        .expect("bootstrap chain emits one ak.member.state envelope for the invitee");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_member_state_event[invite]", &envelope);
}

#[test]
fn build_member_state_transition_event_matches_event_schema() {
    let mut envelope = event_builders::build_member_state_transition_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        TEST_INVITEE_DID,
        Some("invite"),
        "join",
        "invite_accept",
    )
    .expect("build_member_state_transition_event succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_member_state_transition_event", &envelope);
}

#[test]
fn build_plaintext_visible_services_event_matches_event_schema() {
    let mut envelope = event_builders::build_plaintext_visible_services_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        &["did:web:server.example".to_owned()],
    )
    .expect("build_plaintext_visible_services_event succeeds")
    .expect("non-empty service list yields Some(envelope)");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_plaintext_visible_services_event", &envelope);
}

/// The genesis `ak.realm.delivery_binding_policy` value is authored through
/// the SDK `DeliveryBindingPolicyPayload` strong type; this gate pins the
/// emitted body against the closed
/// `event-payload.schema.json#/$defs/realm_delivery_binding_policy_payload`.
///
/// It deliberately does NOT run the envelope gate: `event-envelope.schema.json`
/// routes this kind to the generic `state_payload` (`{value,state,reason}`,
/// `additionalProperties:false`), which contradicts the dedicated flat def the
/// same artifact set declares — and the flat form is what soland's
/// `apply_delivery_binding_policy` / `enforce_delivery_binding_policy` read.
/// Tracked by arkret-work `review/spec-open/
/// 2026-07-30-realm-policy-payload-shape-gaps.md` gap 2.
#[test]
fn realm_bootstrap_delivery_binding_policy_matches_payload_schema() {
    let events = event_builders::build_realm_bootstrap_events(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        TEST_SERVICE_ID,
        "Engineering",
        None,
        "listed",
        "invite",
        "shared",
        "mls_rfc9420",
        "standard",
        "restricted",
        "single_did",
        "sha256",
        "ak:trust_domain:server.example",
        &[],
        &[],
        None,
        None,
    )
    .expect("build_realm_bootstrap_events succeeds");

    let policy = events
        .iter()
        .find(|event| event.kind == EventKind::RealmDeliveryBindingPolicy)
        .cloned()
        .expect("bootstrap chain emits ak.realm.delivery_binding_policy");
    assert_eq!(
        policy.payload["allowed_recipient_services"],
        serde_json::json!([TEST_SERVICE_ID]),
        "the recipient-service allow-list must stay a closed DID list, never the \
         [\"*\"] unrestricted sentinel"
    );
    assert_matches_payload_def(
        "build_realm_bootstrap_events[delivery_binding_policy]",
        "realm_delivery_binding_policy_payload",
        &serde_json::to_value(&policy.payload).expect("payload serializes"),
    );
}

/// The alias carrier landed with spec finding
/// `2026-07-30-realm-object-closed-schema-missing-carriers` gap 1, so the
/// builder no longer refuses an alias — it emits `ak.realm.alias`, and the
/// create object still carries none. What survives from the old refusal gate is
/// its other half: a blank or sigil-only alias is "no alias" and must produce no
/// Event at all, rather than an empty declaration that would occupy the cell.
#[test]
fn blank_alias_is_absence_and_emits_no_alias_event() {
    for blank in ["  ", "#", " # "] {
        let events = event_builders::build_realm_bootstrap_events(
            TEST_REALM_ID,
            TEST_ACTOR_ID,
            TEST_SERVICE_ID,
            "Engineering",
            None,
            "listed",
            "invite",
            "shared",
            "mls_rfc9420",
            "standard",
            "restricted",
            "single_did",
            "sha256",
            "ak:trust_domain:server.example",
            &[],
            &[],
            Some(blank),
            None,
        )
        .expect("an empty alias is indistinguishable from absence");
        assert!(
            !events
                .iter()
                .any(|event| event.kind == EventKind::RealmAlias),
            "a blank alias {blank:?} must not claim the alias cell"
        );
    }
}

/// R94 regression. `realm.schema.json` is closed (46 properties,
/// `unevaluatedProperties: false`) and has no `plaintext_visible_services`
/// property; the fact's only carrier is the dedicated
/// `ak.realm.plaintext_visible_services` Event. The earlier
/// `build_realm_create_event` gate only ever passed an empty service list, so a
/// second declaration on the Realm object survived every schema gate.
///
/// This asserts both halves: a non-empty caller list must keep the create
/// object schema-valid AND must materialize exactly one dedicated facet Event.
#[test]
fn realm_bootstrap_keeps_plaintext_services_off_the_closed_realm_object() {
    let events = event_builders::build_realm_bootstrap_events(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        TEST_SERVICE_ID,
        "Engineering",
        None,
        "listed",
        "invite",
        "shared",
        "mls_rfc9420",
        "standard",
        "restricted",
        "single_did",
        "sha256",
        "ak:trust_domain:server.example",
        &[],
        &["did:web:server.example".to_owned()],
        None,
        None,
    )
    .expect("build_realm_bootstrap_events succeeds");

    let mut create = events
        .iter()
        .find(|event| event.kind == EventKind::RealmCreate)
        .cloned()
        .expect("bootstrap chain emits ak.realm.create");
    assert!(
        create.payload["object"]
            .get("plaintext_visible_services")
            .is_none(),
        "ak.realm.create object must not declare plaintext_visible_services; \
         realm.schema.json is closed and does not define that property"
    );
    stamp_wire_fields(&mut create);
    assert_envelope_matches_schema(
        "build_realm_bootstrap_events[create with plaintext services]",
        &create,
    );

    let facets = events
        .iter()
        .filter(|event| event.kind == EventKind::RealmPlaintextVisibleServices)
        .count();
    assert_eq!(
        facets, 1,
        "the caller's plaintext service list must materialize exactly one \
         ak.realm.plaintext_visible_services Event"
    );
}

/// The sibling of the plaintext-services regression: an alias is also NOT a
/// property of the closed `realm.schema.json`. `ak.realm.alias` is its only
/// wire carrier (object-addressing.md §3.3), and it is a registered
/// seal_basis-exempt bootstrap follow-up (realm-and-space.md §2.5), so a
/// create-time alias must appear as its own Event in the same batch.
///
/// This is the case the old gate could not see: it only ever passed
/// `alias: None`, so the field never reached a validated object.
#[test]
fn realm_bootstrap_carries_alias_as_a_facet_event_not_on_the_closed_realm_object() {
    let events = event_builders::build_realm_bootstrap_events(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        TEST_SERVICE_ID,
        "Engineering",
        None,
        "listed",
        "invite",
        "shared",
        "mls_rfc9420",
        "standard",
        "restricted",
        "single_did",
        "sha256",
        "ak:trust_domain:server.example",
        &[],
        &[],
        Some("#General"),
        None,
    )
    .expect("build_realm_bootstrap_events succeeds");

    let mut create = events
        .iter()
        .find(|event| event.kind == EventKind::RealmCreate)
        .cloned()
        .expect("bootstrap chain emits ak.realm.create");
    assert!(
        create.payload["object"].get("alias").is_none(),
        "ak.realm.create object must not declare alias; realm.schema.json is \
         closed and does not define that property"
    );
    stamp_wire_fields(&mut create);
    assert_envelope_matches_schema("build_realm_bootstrap_events[create with alias]", &create);

    let mut alias_events: Vec<_> = events
        .iter()
        .filter(|event| event.kind == EventKind::RealmAlias)
        .cloned()
        .collect();
    assert_eq!(
        alias_events.len(),
        1,
        "a create-time alias must materialize exactly one ak.realm.alias Event"
    );
    let alias_event = &mut alias_events[0];
    // The `#` share sigil is display-only, and the bare localpart is bound to
    // the deployment authority domain derived from the service DID.
    assert_eq!(
        alias_event.payload["alias"],
        serde_json::json!("general:server.example"),
    );
    stamp_wire_fields(alias_event);
    assert_envelope_matches_schema("build_realm_bootstrap_events[alias facet]", alias_event);
}

/// A managed Agent PCR genesis is a single `ak.realm.create`, and
/// `ak.realm.history_sharing_policy` is absent from the PCR event-kind
/// allowlist, so the effective policy comes from the profile-fixed baseline
/// (`ak.profile.principal_control_realm.v1`). Declaring it on the object put a
/// field on the closed `realm.schema.json` that no schema branch accepts.
#[test]
fn managed_agent_pcr_genesis_leaves_history_sharing_policy_to_the_profile() {
    let events = event_builders::build_managed_agent_pcr_bootstrap_events(
        TEST_REALM_ID,
        "did:web:agent.example",
        TEST_ACTOR_ID,
        "did:web:alice.example#delegation-0",
        "ak:trust_domain:server.example",
        arkret_sdk::EventId::new("ak:event:01964137-0000-7000-8000-000000000098")
            .expect("fixture provision Event id"),
    )
    .expect("build_managed_agent_pcr_bootstrap_events succeeds");

    assert_eq!(
        events.len(),
        1,
        "managed Agent PCR genesis is a single Event"
    );
    let mut create = events[0].clone();
    assert_eq!(create.kind, EventKind::RealmCreate);
    assert!(
        create.payload["object"]
            .get("history_sharing_policy")
            .is_none(),
        "a managed Agent PCR create object must not declare \
         history_sharing_policy; the PCR profile fixes the effective baseline"
    );
    assert!(
        create.payload["object"].get("alias").is_none(),
        "a PCR is addressable only by realm_id"
    );
    stamp_wire_fields(&mut create);
    assert_envelope_matches_schema("build_managed_agent_pcr_bootstrap_events[create]", &create);
}

/// A6 — the SAS public-key exchange sends `ak.key.verification.key`, whose
/// content `device-message.schema.json` constrains: every
/// `ak.key.verification.*` content MUST carry `transaction_id` + `from_device`,
/// and this kind additionally `key`. Inkson sent only the signed proof block,
/// so the message was invalid against the schema on every send — invisible
/// because nothing validated a device message against it. The signed transcript
/// still rides along; that content object is `additionalProperties: true`.
#[test]
fn sas_key_verification_device_message_matches_device_message_schema() {
    let signing = SigningKey::from_bytes(&[11u8; 32]);
    let from_device = "ak:device:01904100-0000-7000-8000-0000000000aa";
    let target_device = "ak:device:01904100-0000-7000-8000-0000000000bb";
    let proof = event_builders::build_signed_device_verification_proof(
        TEST_ACTOR_ID,
        from_device,
        target_device,
        "sas_key",
        None,
        Some("alice-x25519-public"),
        None,
        &signing,
    )
    .expect("build_signed_device_verification_proof succeeds");
    let content = event_builders::build_sas_key_verification_content(
        "0190410000007000800000000abc",
        "alice-x25519-public",
        proof,
    )
    .expect("build_sas_key_verification_content succeeds");

    let request = event_builders::build_device_message_envelope(
        "ak:device_message:01904100-0000-7000-8000-0000000000cc",
        "did:web:bob.example",
        target_device,
        "ak.key.verification.key",
        "2026-04-26T00:10:00.000Z",
        content.clone(),
    )
    .expect("build_device_message_envelope succeeds");
    let request = serde_json::to_value(&request).expect("send request serializes");
    assert_matches_schema(
        "build_device_message_envelope[ak.key.verification.key]",
        "service-operation-dtos.schema.json",
        Some("DeviceMessagesSendRequestBody"),
        &request,
    );

    // The send DTO is closed and carries no sender identity; the delivered
    // envelope is where `key_verification_content` actually applies, so build
    // the server-side view the recipient sees and validate that.
    let target = &request["messages"]["did:web:bob.example"][target_device];
    let delivered = serde_json::json!({
        "message_id": target["message_id"],
        "kind": target["kind"],
        "sender_principal_id": TEST_ACTOR_ID,
        "sender_device_id": from_device,
        "recipient_principal_id": "did:web:bob.example",
        "recipient_device_id": target_device,
        "sent_at": "2026-04-26T00:00:00.000Z",
        "expires_at": target["expires_at"],
        "content": target["content"],
    });
    assert_matches_schema(
        "delivered ak.key.verification.key device message",
        "device-message.schema.json",
        None,
        &delivered,
    );

    // Non-vacuity: the shape this replaced — the bare proof block — must fail
    // the same validator, otherwise the gate proves nothing.
    let mut legacy = delivered.clone();
    legacy["content"] = serde_json::json!({
        "device_envelope": delivered["content"]["device_envelope"],
        "signature": delivered["content"]["signature"],
    });
    let device_message_schema = Value::Object(
        [(
            "$ref".to_owned(),
            Value::String(spec_schema_id("device-message.schema.json")),
        )]
        .into_iter()
        .collect(),
    );
    let validator = jsonschema::options()
        .with_registry(spec_schema_registry())
        .build(&device_message_schema)
        .expect("device-message.schema.json compiles");
    assert!(
        !validator.is_valid(&legacy),
        "the pre-A6 content (proof block only) must fail device-message.schema.json"
    );
}
