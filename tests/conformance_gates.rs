//! Conformance gate: every typed builder in yougen MUST produce an
//! EventEnvelope that validates against contrix-spec event-envelope.schema.json.
//!
//! Stream J of `_claude_todos.md`. Three families of gates live here:
//!
//! 1. **J1 — event-schema gate.** For each typed builder in `yougen::api`, run build → stamp the
//!    wire-only fields a real submitter would attach (`anchor_ref`, `proofs[0]` from a real Ed25519
//!    signer) → serialise → validate against
//!    `contrix-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`. Schema requires reducer-input
//!    events to carry `preconditions`, `effects`, `anchor_ref`, and at least one proof; the gate
//!    therefore covers both the builder output and the sign-and-stamp pipeline immediately
//!    downstream.
//!
//! 2. **J2 — operation_id registry gate.** Recursively scans `yougen/src/**/*.rs` for `operation_id
//!    = "cx.*"` literals and asserts each is in the canonical `operation-registry.json` OR
//!    namespaced as `cx.extension.yougen.*`. Yougen has very few of these (typed Rust API, not
//!    HTTP), but the gate keeps the convention if any are added.
//!
//! 3. **J3 — forbidden terms gate.** Recursively scans `yougen/src/**/*.rs` for legacy names
//!    (`Place`, `place_id`, `BoardPlace`, `PlaceProjection`, `PlaceLifecycleState`, `flow_branch`)
//!    and fails on any occurrence outside `#[cfg(test)]` modules or comment lines.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use jsonschema::{Registry, Resource};
use regex::Regex;
use serde_json::Value;
use walkdir::WalkDir;
use yougen::api;
use yougen::operation::EventEnvelope;

// ----------------------------------------------------------------------
// Shared path / file helpers
// ----------------------------------------------------------------------

fn spec_artifact(path: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("yougen lives next to contrix-spec")
        .join("contrix-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join(path)
}

fn yougen_src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| e.file_name() != "target")
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files
}

fn is_comment_line(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn code_portion(line: &str) -> &str {
    let mut in_str = false;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && in_str {
            i += 2;
            continue;
        }
        if c == b'"' {
            in_str = !in_str;
        } else if !in_str && c == b'/' && bytes[i + 1] == b'/' {
            return &line[..i];
        }
        i += 1;
    }
    line
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
            .unwrap_or("https://contrix.io/artifacts/schemas/event-envelope.schema.json")
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

const TEST_REALM_ID: &str = "cx:realm:0196419b-0000-7000-8000-000000000001";
const TEST_SPACE_ID: &str = "cx:space:0196419b-0000-7000-8000-000000000002";
const TEST_ACTOR_DID: &str = "did:web:alice.example";
const TEST_INVITEE_DID: &str = "did:web:bob.example";
const TEST_ANCHOR_REF: &str =
    "cx:anchor:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Stamp the wire fields the submit pipeline would normally attach
/// (anchor_ref + Ed25519 proof) so the envelope satisfies the
/// "reducer-input requires preconditions/effects/anchor_ref/proofs"
/// rules baked into event-envelope.schema.json.
fn stamp_wire_fields(envelope: &mut EventEnvelope) {
    if envelope.anchor_ref.is_none() {
        envelope.anchor_ref = Some(TEST_ANCHOR_REF.to_owned());
    }
    let signer_did = TEST_ACTOR_DID;
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
        "event_id": "cx:event:not-a-uuid",
        "kind": "cx.realm.create",
        "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000001",
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

    // Reducer-input kind missing preconditions/effects/anchor_ref MUST
    // be rejected per the `then.required` rule on the reducer-kind
    // branch of the top-level `allOf`. If this slips through, the
    // schema validator is silently degraded to a syntax-only checker.
    let reducer_missing_required = serde_json::json!({
        "event_id": "cx:event:0196419b-0000-7777-8000-000000000003",
        "kind": "cx.realm.create",
        "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000001",
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
        "validator accepted a reducer-input cx.realm.create envelope \
         missing preconditions/effects/anchor_ref; the conditional `if/then` \
         branch on event-envelope.schema.json is not being evaluated"
    );
}

/// Validate `envelope` against event-schema. Panics with a readable
/// diff on any schema violation.
fn assert_envelope_matches_schema(label: &str, envelope: &EventEnvelope) {
    assert!(
        !envelope.hlc.is_empty(),
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
        TEST_ACTOR_DID,
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
        "cx:trust_domain:server.example",
        &[],
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
        TEST_ACTOR_DID,
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
        TEST_ACTOR_DID,
        "cx.space.archive",
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
        TEST_ACTOR_DID,
        "cx.space.restore",
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
        TEST_ACTOR_DID,
        "cx.space.tombstone",
    )
    .expect("build_space_lifecycle_event(tombstone) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_space_lifecycle_event[tombstone]", &envelope);
}

#[test]
fn build_space_state_event_join_rule_matches_event_schema() {
    let mut envelope = api::build_space_state_event(
        TEST_REALM_ID,
        TEST_ACTOR_DID,
        "cx.realm.join_rule",
        serde_json::json!("invite"),
    )
    .expect("build_space_state_event(join_rule) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_space_state_event[join_rule]", &envelope);
}

#[test]
fn build_space_state_event_history_visibility_matches_event_schema() {
    let mut envelope = api::build_space_state_event(
        TEST_REALM_ID,
        TEST_ACTOR_DID,
        "cx.realm.history_visibility",
        serde_json::json!("shared"),
    )
    .expect("build_space_state_event(history_visibility) succeeds");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_space_state_event[history_visibility]", &envelope);
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
        TEST_ACTOR_DID,
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
        "cx:trust_domain:server.example",
        &[TEST_INVITEE_DID.to_owned()],
        &[],
    )
    .expect("build_realm_bootstrap_events succeeds");
    let mut envelope = events
        .into_iter()
        .find(|event| event.kind == "cx.member.state")
        .expect("bootstrap chain emits one cx.member.state envelope for the invitee");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_member_state_event[invite]", &envelope);
}

#[test]
fn build_member_state_transition_event_matches_event_schema() {
    let mut envelope = api::build_member_state_transition_event(
        TEST_REALM_ID,
        TEST_ACTOR_DID,
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
        TEST_ACTOR_DID,
        &["did:web:server.example".to_owned()],
    )
    .expect("build_plaintext_visible_services_event succeeds")
    .expect("non-empty service list yields Some(envelope)");
    stamp_wire_fields(&mut envelope);
    assert_envelope_matches_schema("build_plaintext_visible_services_event", &envelope);
}

// ----------------------------------------------------------------------
// J2 — Operation registry gate (yougen)
// ----------------------------------------------------------------------

fn load_canonical_operation_ids() -> BTreeSet<String> {
    let path = spec_artifact("registry/operation-registry.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {} failed: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("parse {} failed: {err}", path.display()));
    let mut out = BTreeSet::new();
    collect_operation_ids(&value, &mut out);
    assert!(
        !out.is_empty(),
        "operation-registry.json contained zero operation_id values"
    );
    out
}

fn collect_operation_ids(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "operation_id" {
                    if let Some(id) = child.as_str() {
                        out.insert(id.to_owned());
                    }
                } else if key == "operations"
                    && let Some(array) = child.as_array()
                {
                    for entry in array {
                        if let Some(id) = entry.as_str() {
                            out.insert(id.to_owned());
                        } else {
                            collect_operation_ids(entry, out);
                        }
                    }
                    continue;
                }
                collect_operation_ids(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_operation_ids(item, out);
            }
        }
        _ => {}
    }
}

#[test]
fn yougen_operation_ids_are_registered_or_namespaced() {
    let canonical = load_canonical_operation_ids();
    let pattern =
        Regex::new(r#"operation_id\s*=\s*"(cx\.[A-Za-z0-9_.]+)""#).expect("regex compiles");

    let mut offenders: Vec<String> = Vec::new();
    for path in rust_files(&yougen_src_root()) {
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for (idx, line) in raw.lines().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            let scanned = code_portion(line);
            for cap in pattern.captures_iter(scanned) {
                let op = &cap[1];
                if op.starts_with("cx.extension.yougen.") {
                    continue;
                }
                if canonical.contains(op) {
                    continue;
                }
                offenders.push(format!(
                    "{}:{}: unregistered operation_id `{op}` (not in canonical \
                     registry and not namespaced as cx.extension.yougen.*)",
                    path.display(),
                    idx + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "yougen source declares operation_id values that are neither \
         in the canonical registry nor namespaced as \
         cx.extension.yougen.*:\n  {}",
        offenders.join("\n  ")
    );
}

// ----------------------------------------------------------------------
// J3 — Forbidden terms gate (yougen)
// ----------------------------------------------------------------------

#[test]
fn yougen_source_tree_is_free_of_forbidden_legacy_terms() {
    let patterns: Vec<(Regex, &str)> = vec![
        (Regex::new(r"\bPlace\b").unwrap(), "bare type `Place`"),
        (
            Regex::new(r"\bplace_id\b").unwrap(),
            "field name `place_id`",
        ),
        (Regex::new(r"\bBoardPlace\b").unwrap(), "type `BoardPlace`"),
        (
            Regex::new(r"\bPlaceProjection\b").unwrap(),
            "type `PlaceProjection`",
        ),
        (
            Regex::new(r"\bPlaceLifecycleState\b").unwrap(),
            "type `PlaceLifecycleState`",
        ),
        (
            Regex::new(r"\bflow_branch\b").unwrap(),
            "field `flow_branch`",
        ),
    ];

    let mut offenders: Vec<String> = Vec::new();
    for path in rust_files(&yougen_src_root()) {
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let test_ranges = cfg_test_ranges(&raw);
        for (idx, line) in raw.lines().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            let line_offset = line_byte_offset(&raw, idx);
            if test_ranges
                .iter()
                .any(|(start, end)| line_offset >= *start && line_offset < *end)
            {
                continue;
            }
            let scanned = code_portion(line);
            for (re, label) in &patterns {
                if re.is_match(scanned) {
                    offenders.push(format!(
                        "{}:{}: forbidden term {label} in production code: `{}`",
                        path.display(),
                        idx + 1,
                        scanned.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "yougen production code contains legacy terms that were renamed \
         during the Realm/Space inversion (Stream B/C):\n  {}",
        offenders.join("\n  ")
    );
}

fn cfg_test_ranges(source: &str) -> Vec<(usize, usize)> {
    let needle = "#[cfg(test)]";
    let bytes = source.as_bytes();
    let mut ranges = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(needle) {
        let attr_start = search_from + rel;
        let mut cursor = attr_start + needle.len();
        while cursor < bytes.len() && bytes[cursor] != b'{' {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        let body_start = cursor;
        let mut depth: i32 = 0;
        let mut in_str = false;
        let mut in_line_comment = false;
        let mut prev_was_slash = false;
        let mut i = cursor;
        while i < bytes.len() {
            let c = bytes[i];
            if in_line_comment {
                if c == b'\n' {
                    in_line_comment = false;
                }
                i += 1;
                continue;
            }
            if in_str {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if c == b'/' && prev_was_slash {
                in_line_comment = true;
                prev_was_slash = false;
                i += 1;
                continue;
            }
            prev_was_slash = c == b'/';
            if c == b'"' {
                in_str = true;
            } else if c == b'{' {
                depth += 1;
            } else if c == b'}' {
                depth -= 1;
                if depth == 0 {
                    ranges.push((body_start, i + 1));
                    search_from = i + 1;
                    break;
                }
            }
            i += 1;
        }
        if depth != 0 {
            break;
        }
    }
    ranges
}

fn line_byte_offset(source: &str, line_index: usize) -> usize {
    let mut offset = 0;
    for (idx, line) in source.lines().enumerate() {
        if idx == line_index {
            return offset;
        }
        offset += line.len() + 1;
    }
    source.len()
}
