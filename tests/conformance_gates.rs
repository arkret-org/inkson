//! Conformance gate: every typed builder in yougen MUST produce an
//! EventEnvelope that validates against cokret-spec event-envelope.schema.json.
//!
//! Stream J of `_claude_todos.md`: for each typed builder in `yougen::api`,
//! run build, stamp the wire-only fields a real submitter would attach
//! (`seal_ref`, `proofs[0]` from a real Ed25519 signer), serialise, and validate
//! against `cokret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`.
//! Schema requires reducer-input events to carry `preconditions`, `effects`,
//! `seal_ref`, and at least one proof; the gate therefore covers both the
//! builder output and the sign-and-stamp pipeline immediately downstream.

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use jsonschema::{Registry, Resource};
use serde_json::Value;
use yougen::api;
use yougen::operation::{EventEnvelope, EventEnvelopeExt, EventKind};

// ----------------------------------------------------------------------
// Shared path / file helpers
// ----------------------------------------------------------------------

fn spec_artifact(path: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("yougen lives next to cokret-spec")
        .join("cokret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join(path)
}

// ----------------------------------------------------------------------
// J1 — Event-schema validation gate
// ----------------------------------------------------------------------

/// Compile the event-schema once per test process.
fn event_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let event_schema_path = spec_artifact("schemas/event-envelope.schema.json");
        let schemas_dir = spec_artifact("schemas");

        let event_schema_raw = fs::read_to_string(&event_schema_path).unwrap_or_else(|err| {
            panic!("read {} failed: {err}", event_schema_path.display());
        });
        let event_schema: Value = serde_json::from_str(&event_schema_raw)
            .expect("event-envelope.schema.json parses as JSON");

        let event_schema_id = event_schema
            .get("$id")
            .and_then(Value::as_str)
            .unwrap_or("https://cokret.org/v1/schemas/event-envelope.schema.json")
            .to_owned();

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

        let registry = registry.prepare().expect("schema registry prepares");

        jsonschema::options()
            .with_registry(&registry)
            .with_base_uri(event_schema_id.as_str())
            .build(&event_schema)
            .expect("event-schema compiles")
    })
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

const TEST_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000001";
const TEST_SPACE_ID: &str = "ck:space:0196419b-0000-7000-8000-000000000002";
const TEST_ACTOR_ID: &str = "did:web:alice.example";
const TEST_INVITEE_DID: &str = "did:web:bob.example";
const TEST_ANCHOR_REF: &str =
    "ck:seal:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Stamp the wire fields the submit pipeline would normally attach
/// (seal_ref + Ed25519 proof) so the envelope satisfies the
/// "reducer-input requires preconditions/effects/seal_ref/proofs"
/// rules baked into event-envelope.schema.json.
fn stamp_wire_fields(envelope: &mut EventEnvelope) {
    if envelope.seal_ref.is_none() {
        envelope.seal_ref =
            Some(cokret_sdk::SealId::new(TEST_ANCHOR_REF.to_owned()).expect("test seal ref"));
    }
    let signer_did = TEST_ACTOR_ID;
    let key_id = format!("{signer_did}#device");
    envelope
        .sign_ed25519(signer_did, key_id, test_signing_key())
        .expect("Ed25519 sign succeeds for schema-conformant envelope");
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
        "event_id": "ck:event:not-a-uuid",
        "kind": "ck.realm.create",
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000001",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1,
        "created_at": "2026-05-21T13:00:00Z",
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
        "event_id": "ck:event:0196419b-0000-7777-8000-000000000003",
        "kind": "ck.realm.create",
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000001",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1,
        "created_at": "2026-05-21T13:00:00Z",
        "prev_refs": [],
        "refs": [],
        "payload": {},
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example#device",
            "event_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "created_at": "2026-05-21T13:00:00Z",
            "jws": "a.b.c"
        }]
    });
    assert!(
        !validator.is_valid(&reducer_missing_required),
        "validator accepted a reducer-input ck.realm.create envelope \
         missing preconditions/effects/seal_ref; the conditional `if/then` \
         branch on event-envelope.schema.json is not being evaluated"
    );
}

/// Validate `envelope` against event-schema. Panics with a readable
/// diff on any schema violation.
fn assert_envelope_matches_schema(label: &str, envelope: &EventEnvelope) {
    assert!(
        !envelope.hlc.as_str().is_empty(),
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
    let mut envelope = api::build_realm_create_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
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
        "ck:trust_domain:server.example",
        &[],
        None,
        None,
    )
    .expect("build_realm_create_event succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_realm_create_event", &envelope);
}

#[test]
fn build_space_create_event_matches_event_schema() {
    let mut envelope = api::build_space_create_event(
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
    let mut envelope = api::build_space_lifecycle_event(
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
    let mut envelope = api::build_space_lifecycle_event(
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
    let mut envelope = api::build_space_lifecycle_event(
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
    let mut envelope = api::build_realm_state_event(
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
    let mut envelope = api::build_realm_state_event(
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
    let mut envelope = api::build_realm_history_sharing_policy_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        serde_json::json!({
            "version": 1,
            "default_key_share": "event_time_visibility",
            "allowed_key_sources": ["verified_member_device"],
            "allowed_receiver_states": ["active_member"],
            "audit": {
                "share_audit_event_required": true,
                "access_audit_required": true
            }
        }),
    )
    .expect("build_realm_history_sharing_policy_event succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_realm_state_event[history_sharing_policy]", &envelope);
}

#[test]
fn build_realm_preview_policy_event_matches_event_schema() {
    let mut envelope = api::build_realm_preview_policy_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
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
    .expect("build_realm_preview_policy_event succeeds");
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
    let events = api::build_realm_bootstrap_events(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
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
        "ck:trust_domain:server.example",
        &[TEST_INVITEE_DID.to_owned()],
        &[],
        None,
        None,
    )
    .expect("build_realm_bootstrap_events succeeds");
    let mut envelope = events
        .into_iter()
        .find(|event| event.kind == EventKind::MemberState)
        .expect("bootstrap chain emits one ck.member.state envelope for the invitee");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_member_state_event[invite]", &envelope);
}

#[test]
fn build_member_state_transition_event_matches_event_schema() {
    let mut envelope = api::build_member_state_transition_event(
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
    let mut envelope = api::build_plaintext_visible_services_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        &["did:web:server.example".to_owned()],
    )
    .expect("build_plaintext_visible_services_event succeeds")
    .expect("non-empty service list yields Some(envelope)");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_plaintext_visible_services_event", &envelope);
}
