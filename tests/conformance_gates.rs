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
use inkson::operation::{AuthoredEventExt, Event, EventKind, LocalOperation};

mod common;
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
        "AuthoredEvent::finalize(",
        ".author_now(",
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
        "Realm authoring and verification must name an explicit digest suite: the identity is derived under it, and the signer verifies against the suite the Event was authored under rather than choosing one:
{}",
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

const TEST_REALM_ID: &str = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
const TEST_SPACE_ID: &str = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
const TEST_ACTOR_ID: &str = "ak:did_core:web:alice.example";
const TEST_ACTOR_DID: &str = "did:web:alice.example";
const TEST_SERVICE_ID: &str = "ak:did_core:web:server.example";
const TEST_SERVICE_DID: &str = "did:web:server.example";
const TEST_INVITEE_DID: &str = "did:web:bob.example";
const TEST_ANCHOR_REF: &str =
    "ak:seal:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn test_genesis_salt() -> arkret_sdk::GenesisSalt {
    select_authoring_station();
    arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .expect("test Realm genesis salt is canonical")
}

fn select_authoring_station() {
    inkson::operation::set_authoring_station_id(Some(
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned())
            .expect("test Station core id is canonical"),
    ));
}

/// Stamp the wire fields the submit pipeline would normally attach
/// (CBS basis + Ed25519 proof) so the envelope satisfies the reducer-input
/// rules baked into event-envelope.schema.json.
fn wire_envelope(operation: LocalOperation) -> arkret_sdk::AuthoredEvent {
    wire_envelope_from_intent(operation.into_intent())
}

/// Attach the producer proof to an envelope that is already authored.
///
/// A genesis unit's members are authored together, and every one of them is
/// CBS-exempt, so there is nothing left to stamp before signing.
fn sign_authored(envelope: &mut arkret_sdk::AuthoredEvent) {
    let signer_did = TEST_ACTOR_DID;
    let key_id = format!("{signer_did}#device");
    envelope
        .sign_ed25519(
            signer_did,
            key_id,
            test_signing_key(),
            arkret_sdk::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
        )
        .expect("Ed25519 sign succeeds for schema-conformant envelope");
}

/// The Realm genesis unit, authored the way the submit lane authors it.
fn authored_realm_bootstrap(
    plaintext_visible_services: &[String],
    alias: Option<&str>,
) -> Vec<arkret_sdk::AuthoredEvent> {
    common::author_unit(
        event_builders::build_realm_bootstrap_steps_for_station(
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
            test_genesis_salt(),
            TEST_ACTOR_ID,
            TEST_SERVICE_DID,
            common::test_notary(TEST_SERVICE_DID),
            "https://server.example",
            "Engineering",
            None,
            "listed",
            "invite",
            "since_join",
            "mls_rfc9420",
            "standard",
            "restricted",
            "sha256",
            "ak:trust_domain:server.example",
            plaintext_visible_services,
            alias,
            None,
        )
        .expect("build_realm_bootstrap_steps succeeds"),
    )
}

/// Stamp the members a real submitter attaches, then finalize and sign.
///
/// Every one of these is producer-signed content, so it has to be in place
/// BEFORE the identity is derived from it — which is why this returns an
/// authored envelope instead of mutating one.
fn wire_envelope_from_intent(intent: inkson::operation::EventIntent) -> arkret_sdk::AuthoredEvent {
    let mut intent = intent;
    // Control Move: `seal_basis` and nothing from the data-plane pair.
    if intent.kind().is_control_plane() && !cbs_exempt_reducer_kind(intent.kind()) {
        if intent.seal_basis().is_none() {
            intent = intent.with_seal_basis(test_seal_basis());
        }
    // Ordinary Event: the signed auth context carries verified authority references
    // and forbids a Control Move `seal_basis` alongside it.
    } else if intent.kind().is_data_plane() {
        if intent.auth_context().is_none() {
            intent = intent.with_auth_context(test_auth_context());
        }
    }
    let mut envelope = common::author_intent_at_seq(intent, 1);
    let signer_did = TEST_ACTOR_DID;
    let key_id = format!("{signer_did}#device");
    envelope
        .sign_ed25519(
            signer_did,
            key_id,
            test_signing_key(),
            arkret_sdk::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
        )
        .expect("Ed25519 sign succeeds for schema-conformant envelope");
    envelope
}

/// Kinds a real submitter builds WITHOUT `seal_basis` because they sit in the
/// Realm genesis batch, where no accepted Seal exists yet
/// (realm-and-space.md §2.5). Read from the shared SDK helper rather than a
/// local hand-list: a second copy of a closed protocol list is exactly the
/// drift that lets a bootstrap follow-up go untested.
fn cbs_exempt_reducer_kind(kind: &EventKind) -> bool {
    kind == &EventKind::RealmCreate
        || arkret_policy::realm_bootstrap::is_realm_bootstrap_followup_kind(kind)
}

/// The key coordinates and verified authority decision an ordinary Event pins.
fn test_auth_context() -> arkret_sdk::AuthContext {
    arkret_sdk::AuthContext {
        // `key_id` is the bare verification-method fragment with the `ak:`
        // sigil dropped (the schema pattern forbids both `#` and the typed-ID
        // lexical space), which is what `ordinary_event_key_id_for` produces from
        // the active signer's device id.
        key_id: arkret_sdk::OpaqueLocalId::new("device").unwrap(),
        key_epoch: 0,
        credential_epoch: None,
        authority_refs: vec![
            arkret_sdk::SealId::new(TEST_ANCHOR_REF.to_owned())
                .expect("test authority ref is canonical"),
        ],
    }
}

fn test_seal_basis() -> arkret_sdk::SealBasis {
    let view: arkret_sdk::RealmSealFrontierView = serde_json::from_value(serde_json::json!({
        "kind": "realm_seal",
        "realm_id": TEST_REALM_ID,
        "seal_basis": {
            "leaves": [TEST_ANCHOR_REF]
        },
        "governance_health": {
            "status": "healthy",
            "pending_proposals": [],
            "pending_proposals_complete": true
        },
        "observation_coordinate": {
            "service_id": "ak:did_core:web:server.example",
            "sequence": 1,
            "observed_at": "2026-05-21T13:00:00.000Z"
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

    // Correct envelope shape but an invalid Event identity token.
    let bogus = serde_json::json!({
        "event_id": "ak:event:ARVsG4AMRBL8f5CJIY_5XgOEXn-Y-qGjMws333Urc-KI",
        "kind": "ak.realm.create",
        "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "actor_id": "ak:did_core:web:alice.example",
        "actor_seq": 1,
        "created_at": "2026-05-21T13:00:00.000Z",
        "prev_refs": [],
        "payload": {},
        "proofs": []
    });
    assert!(
        !validator.is_valid(&bogus),
        "validator accepted a malformed event_id; resolver wiring is broken"
    );

    // Reducer-input kind missing preconditions/effects MUST
    // be rejected per the `then.required` rule on the reducer-kind
    // branch of the top-level `allOf`. If this slips through, the
    // schema validator is silently degraded to a syntax-only checker.
    let reducer_missing_required = serde_json::json!({
        "event_id": "ak:event:AZEAhO4CFzelWMJKtLZI-HSeK3Nh28YP3M24_4uLoFAF",
        "kind": "ak.realm.create",
        "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "actor_id": "ak:did_core:web:alice.example",
        "actor_seq": 1,
        "created_at": "2026-05-21T13:00:00.000Z",
        "prev_refs": [],
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
         missing preconditions/effects; the conditional `if/then` \
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
    let envelope = event_builders::build_realm_create_event(
        test_genesis_salt(),
        TEST_ACTOR_ID,
        common::test_notary(TEST_SERVICE_DID),
        "Engineering",
        Some("Roadmap work"),
        "listed",
        "invite",
        "since_join",
        "mls_rfc9420",
        "standard",
        "restricted",
        "sha256",
        "ak:trust_domain:server.example",
        None,
    )
    .expect("build_realm_create_event succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_realm_create_event", &envelope);
}

#[test]
fn build_space_create_event_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_space_create_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        "Launch checklist",
        Some("Quarterly launch tracking"),
        "list",
        None,
    )
    .expect("build_space_create_event succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_space_create_event", &envelope);
}

#[test]
fn build_space_lifecycle_event_archive_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_space_lifecycle_event(
        TEST_SPACE_ID,
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::SpaceArchive,
    )
    .expect("build_space_lifecycle_event(archive) succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_space_lifecycle_event[archive]", &envelope);
}

#[test]
fn build_space_lifecycle_event_restore_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_space_lifecycle_event(
        TEST_SPACE_ID,
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::SpaceRestore,
    )
    .expect("build_space_lifecycle_event(restore) succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_space_lifecycle_event[restore]", &envelope);
}

#[test]
fn build_space_lifecycle_event_tombstone_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_space_lifecycle_event(
        TEST_SPACE_ID,
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        EventKind::SpaceTombstone,
    )
    .expect("build_space_lifecycle_event(tombstone) succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_space_lifecycle_event[tombstone]", &envelope);
}

#[test]
fn build_realm_state_event_join_rule_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_realm_state_event_for_station::<
        arkret_sdk::event_spec::RealmJoinRule,
    >(
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        arkret_sdk::DigestSuite::Sha256,
        arkret_sdk::RealmJoinRulePayload::new(arkret_sdk::RealmJoinRuleValue::Invite),
    )
    .expect("build_realm_state_event(join_rule) succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_realm_state_event[join_rule]", &envelope);
}

#[test]
fn build_realm_state_event_history_access_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_realm_state_event_for_station::<
        arkret_sdk::event_spec::RealmHistoryAccess,
    >(
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        arkret_sdk::DigestSuite::Sha256,
        arkret_sdk::HistoryAccessPayload::tighten(),
    )
    .expect("build_realm_state_event(history_access) succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_realm_state_event[history_access]", &envelope);
}

#[test]
fn build_realm_preview_policy_event_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_realm_state_event_for_station::<
        arkret_sdk::event_spec::RealmPreviewPolicy,
    >(
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        arkret_sdk::DigestSuite::Sha256,
        serde_json::from_value(serde_json::json!({
            "value": {
                "mode": "stripped_state",
                "audiences": ["link_token_holder"],
                "fields": ["title", "summary", "join_rule", "history_access"],
                "token": {
                    "required": true,
                    "ttl_seconds": 600,
                    "bind_target_digest": true
                }
            }
        }))
        .expect("preview policy fixture is typed"),
    )
    .expect("build_realm_state_event(preview_policy) succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_realm_state_event[preview_policy]", &envelope);
}

#[test]
fn build_member_state_transition_event_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_member_state_transition_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        &arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::project_did_to_core_id(&arkret_sdk::Did::new(TEST_INVITEE_DID).unwrap())
                .unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        )),
        Some("invite"),
        "join",
        "invite_accept",
    )
    .expect("build_member_state_transition_event succeeds");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_member_state_transition_event", &envelope);
}

#[test]
fn build_plaintext_visible_services_event_matches_event_schema() {
    select_authoring_station();
    let envelope = event_builders::build_plaintext_visible_services_event(
        TEST_REALM_ID,
        TEST_ACTOR_ID,
        &[TEST_SERVICE_ID.to_owned()],
    )
    .expect("build_plaintext_visible_services_event succeeds")
    .expect("non-empty service list yields Some(envelope)");
    let envelope = wire_envelope(envelope);
    assert_envelope_matches_schema("build_plaintext_visible_services_event", &envelope);
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
        let events = authored_realm_bootstrap(&[], Some(blank));
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
    let events = authored_realm_bootstrap(&[TEST_SERVICE_ID.to_owned()], None);

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
    sign_authored(&mut create);
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
    let events = authored_realm_bootstrap(&[], Some("#General"));

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
    sign_authored(&mut create);
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
    sign_authored(alias_event);
    assert_envelope_matches_schema("build_realm_bootstrap_events[alias facet]", alias_event);
}

/// The controller freezes the exact PCR create locally and derives the Realm
/// id from it before authoring the provision declaration.
#[test]
fn agent_pcr_prepare_builds_an_exact_ref_free_create() {
    select_authoring_station();
    let agent_did = arkret_sdk::Did::new("did:web:agent.example").unwrap();
    let root_public_key = common::test_inception_root_key_multibase(agent_did.as_str());
    let events = common::author_unit(
        event_builders::build_agent_pcr_bootstrap_steps(
            agent_did.as_str(),
            arkret_sdk::ResolutionCommitment {
                did: agent_did.clone(),
                method_history_head: format!("sha256:{}", "8".repeat(64)),
                version_id: "1-Qmfixture".to_owned(),
            },
            event_builders::agent_inception_notary(&agent_did, &root_public_key).unwrap(),
            TEST_ACTOR_ID,
            "did:web:alice.example#delegation-0",
            "ak:trust_domain:server.example",
        )
        .expect("Agent provision can freeze an event-derived PCR create"),
    );
    assert_eq!(events.len(), 1);
    assert!(events[0].refs.is_empty());
}

/// A6 — the SAS public-key exchange sends `ak.key.verification.key`, whose
/// content `device-message.schema.json` constrains: every
/// `ak.key.verification.*` content MUST carry `transaction_id` + `from_device_id`,
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
        TEST_ACTOR_DID,
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

    let request = arkret_sdk::TypedDeviceMessageTarget::<
        arkret_sdk::device_message_spec::KeyVerificationKey,
    >::new(
        arkret_sdk::DeviceMessageId::new("ak:device_message:01904100-0000-7000-8000-0000000000cc")
            .expect("fixture message id"),
        "2026-04-26T00:10:00.000Z"
            .parse()
            .expect("fixture expiration"),
        content.clone(),
    )
    .expect("typed key-verification target")
    .single_recipient(
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").expect("fixture recipient"),
        arkret_sdk::DeviceId::new(target_device).expect("fixture target device"),
    )
    .expect("build typed device-message request");
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
    let target = &request["messages"]["ak:did_core:web:bob.example"][target_device];
    let delivered = serde_json::json!({
        "device_message_id": target["device_message_id"],
        "kind": target["kind"],
        "sender_account_id": {
            "principal_id": "ak:did_core:web:alice.example",
            "station_id": "ak:did_core:web:alice-station.example"
        },
        "sender_device_id": from_device,
        "recipient_account_id": {
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:bob-station.example"
        },
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
}
