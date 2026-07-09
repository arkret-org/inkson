use serde_json::{Value, json};

use super::*;

fn assert_registered_payload_valid(event: &EventEnvelope) {
    let catalog = cokret_sdk::schema::event_payload_validator_catalog().unwrap();
    catalog
        .validate_payload(event.kind.as_str(), &event.payload)
        .unwrap_or_else(|err| {
            panic!(
                "{} payload violates registered spec schema: {err}\npayload: {}",
                event.kind,
                serde_json::to_string_pretty(&event.payload).unwrap()
            );
        });
}

fn assert_payload_field_names_are_spec_canonical(value: &serde_json::Value) {
    fn check(value: &serde_json::Value) -> Result<(), String> {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    check(value)?;
                }
            }
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    let name_part = key.strip_prefix('$').unwrap_or(key);
                    if name_part.is_empty()
                        || !name_part
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                        || name_part.starts_with('_')
                        || name_part.ends_with('_')
                        || name_part.contains("__")
                    {
                        return Err(format!("non-canonical field name {key:?}"));
                    }
                    check(value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    check(value).unwrap_or_else(|err| {
        panic!("payload violates soland canonical JSON gate: {err}\npayload: {value}")
    });
}

#[test]
fn proof_mode_labels_are_distinct() {
    let modes = [
        ProofMode::RealEd25519,
        ProofMode::ExternalSigner,
        ProofMode::Production,
    ];
    let labels: Vec<_> = modes.iter().map(|m| m.label_en()).collect();
    let i18n_keys: Vec<_> = modes.iter().map(|m| m.i18n_key()).collect();
    for label in &labels {
        assert_eq!(labels.iter().filter(|l| **l == *label).count(), 1);
    }
    for key in &i18n_keys {
        assert_eq!(i18n_keys.iter().filter(|k| **k == *key).count(), 1);
    }
}

#[test]
fn operation_builder_generates_valid_envelope() {
    let op = OperationBuilder::new(
        "ck:realm:0196419b-0000-7000-8000-0000000000aa",
        "did:web:alice",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"content": {"kind": "ck.content.text", "body": "hello"}}))
    .build("test_node");

    assert!(!op.local_operation_id().is_empty());
    assert_eq!(
        op.realm_id.as_str(),
        "ck:realm:0196419b-0000-7000-8000-0000000000aa"
    );
    assert_eq!(op.actor_id.as_str(), "did:web:alice");
    assert_eq!(op.kind.as_str(), "ck.message.create");
    assert!(!op.hlc.as_str().is_empty());
    assert!(op.actor_seq > 0);
    // Spec compliance: build() never attaches a placeholder proof —
    // the submit path requires an installed signer.
    assert!(op.proofs.is_empty());
}

#[test]
fn operation_round_trip_serde() {
    let op = OperationBuilder::new(
        "ck:realm:0196419b-0000-7000-8000-0000000000ab",
        "did:web:bob",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"content": {"kind": "ck.content.text", "body": "hello world"}}))
    .build("node");
    let json = serde_json::to_string(&op).unwrap();
    let parsed: EventEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(op, parsed);
}

#[test]
fn operation_builder_can_emit_signed_authorization_binding() {
    let op = OperationBuilder::new(
        "ck:realm:0196419b-0000-7000-8000-0000000000ab",
        "did:web:bob",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"content": {"kind": "ck.content.text", "body": "hello world"}}))
    .executed_by("did:web:agent.example")
    .authorization_ref("ck:grant:0196419b-0000-7000-8000-000000000001")
    .build("node");

    assert_eq!(
        op.executed_by.as_ref().map(|did| did.as_str()),
        Some("did:web:agent.example")
    );
    assert_eq!(
        op.authorization_ref.as_deref(),
        Some("ck:grant:0196419b-0000-7000-8000-000000000001")
    );
    assert!(op.unsigned.get("local_authz_ref").is_none());

    let mut canonical = serde_json::to_value(&op).unwrap();
    if let serde_json::Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
    }
    assert_eq!(canonical["executed_by"], "did:web:agent.example");
    assert_eq!(
        canonical["authorization_ref"],
        "ck:grant:0196419b-0000-7000-8000-000000000001"
    );
}

#[test]
fn event_envelope_accepts_current_optional_top_level_fields() {
    let op = OperationBuilder::new(
        "ck:realm:0196419b-0000-7000-8000-0000000000ab",
        "did:web:bob",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"content": {"kind": "ck.content.text", "body": "hello world"}}))
    .build("node");
    let mut value = serde_json::to_value(&op).unwrap();
    let object = value.as_object_mut().unwrap();
    object.insert(
        "effective_scope".to_owned(),
        json!({"kind": "realm", "realm_id": "ck:realm:0196419b-0000-7000-8000-0000000000ab"}),
    );
    object.insert("executed_by".to_owned(), json!("did:web:agent.example"));
    object.insert(
        "authorization_ref".to_owned(),
        json!("ck:grant:0196419b-0000-7000-8000-000000000001"),
    );
    object.insert("actor_kind".to_owned(), json!("agent"));

    let parsed: EventEnvelope = serde_json::from_value(value).unwrap();
    assert_eq!(
        parsed.effective_scope,
        Some(cokret_sdk::models::EffectiveScope::Realm {
            realm_id: cokret_sdk::RealmId::new(
                "ck:realm:0196419b-0000-7000-8000-0000000000ab".to_owned()
            )
            .unwrap(),
        })
    );
    assert_eq!(
        parsed.executed_by.as_ref().map(|did| did.as_str()),
        Some("did:web:agent.example")
    );
    assert_eq!(
        parsed.authorization_ref.as_deref(),
        Some("ck:grant:0196419b-0000-7000-8000-000000000001")
    );
    assert_eq!(
        parsed.actor_kind,
        Some(cokret_sdk::EnvelopeActorKind::Agent)
    );
}

#[test]
fn event_envelope_rejects_unknown_top_level_fields() {
    let op = OperationBuilder::new(
        "ck:realm:0196419b-0000-7000-8000-0000000000ab",
        "did:web:bob",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"content": {"kind": "ck.content.text", "body": "hello world"}}))
    .build("node");
    let mut value = serde_json::to_value(&op).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("sender".to_owned(), json!("did:web:removed.example"));

    assert!(
        serde_json::from_value::<EventEnvelope>(value).is_err(),
        "deprecated/unknown top-level envelope fields must fail closed"
    );
}

#[test]
fn kanban_card_strand_create_carries_position_in_metadata_fields() {
    let op = ck_ops::kanban_card_strand_create(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice.example",
        "ck:strand:0196419b-0000-7000-8000-000000000004",
        "ck:space:0196419b-0000-7000-8000-000000000002",
        "ck:space:0196419b-0000-7000-8000-000000000003",
        "Move-backed card",
        "h1",
    )
    .expect("builds")
    .build("node");

    assert_eq!(op.kind.as_str(), "ck.strand.create");
    assert_eq!(
        op.realm_id.as_str(),
        "ck:realm:0196419b-0000-7000-8000-000000000001"
    );
    assert_eq!(
        op.payload["object"]["realm_id"],
        "ck:realm:0196419b-0000-7000-8000-000000000001"
    );
    assert_eq!(
        op.payload["object"]["tracks"]["synthesis"]["profile"],
        "kanban_card"
    );
    assert_eq!(
        op.payload["object"]["metadata"]["fields"]["board_space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000002"
    );
    assert_eq!(
        op.payload["object"]["metadata"]["fields"]["list_space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000003"
    );
    assert_eq!(
        op.payload["object"]["metadata"]["title"],
        "Move-backed card"
    );
    assert!(op.payload["object"].get("fields").is_none());
    assert!(op.payload["object"].get("title").is_none());
    assert!(op.payload["object"].get("space_id").is_none());
    assert!(op.payload.get("components").is_none());
    assert!(op.payload.get("patch").is_none());
    assert_registered_payload_valid(&op);
    assert_payload_field_names_are_spec_canonical(&op.payload);
}

#[test]
fn mls_commit_builder_matches_registered_payload_schema() {
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let group_id = "ck:mls_group:kanban-test";
    let governance_binding = cokret_sdk::MlsGovernanceBindingPayload::realm(
        cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
        group_id,
        0,
        1,
        vec![
            cokret_sdk::EventId::new("ck:event:0196419b-0000-7000-8000-000000000002".to_owned())
                .unwrap(),
        ],
        cokret_sdk::Hash::new(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        )
        .unwrap(),
        cokret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        cokret_sdk::CORE_REDUCER_PROFILE,
    )
    .unwrap();
    let payload = cokret_sdk::MlsCommitPayload::new(
        group_id,
        0,
        "ck:event:0196419b-0000-7000-8000-000000000001",
        Vec::new(),
        1,
        cokret_sdk::Hash::new(
            "sha256:7777777777777777777777777777777777777777777777777777777777777777".to_owned(),
        )
        .unwrap(),
        governance_binding,
    )
    .unwrap();
    let op = ck_ops::mls_commit_with_governance(realm_id, "did:web:alice.example", &payload)
        .unwrap()
        .build("node");

    assert_eq!(op.kind.as_str(), "ck.mls.commit");
    assert!(op.payload.get("group_id").is_none());
    assert!(op.payload.get("preconditions").is_none());
    assert!(op.payload.get("effects").is_none());
    assert_registered_payload_valid(&op);
    assert_payload_field_names_are_spec_canonical(&op.payload);
}

#[test]
fn incident_status_update_uses_schema_safe_fields_patch() {
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000002";
    let op = ck_ops::incident_status_update(
        "ck:realm:0196419b-0000-7000-8000-000000000010",
        "did:web:alice.example",
        strand_id,
        "mitigated",
    )
    .expect("builds")
    .build("node");

    assert_eq!(op.kind.as_str(), "ck.strand.update");
    assert_eq!(op.payload["target_ref"], strand_id);
    assert!(op.payload.get("strand_id").is_none());
    assert!(op.payload["patch"].get("fields.status").is_none());
    assert_eq!(
        op.payload["patch"]["fields"]["value"]["status"],
        "mitigated"
    );
    assert_registered_payload_valid(&op);
    assert_payload_field_names_are_spec_canonical(&op.payload);
}

#[test]
fn discussion_strand_create_emits_discussion_track() {
    let op = ck_ops::discussion_strand_create(
        "ck:realm:0196419b-0000-7000-8000-000000000000",
        "did:web:alice.example",
        "ck:strand:0196419b-0000-7000-8000-000000000001",
        "Ops",
    )
    .unwrap()
    .build("node");
    assert_eq!(op.kind.as_str(), "ck.strand.create");
    assert_eq!(
        op.payload["object"]["id"],
        "ck:strand:0196419b-0000-7000-8000-000000000001"
    );
    assert!(op.payload.get("strand_id").is_none());
    assert_eq!(
        op.payload["object"]["tracks"]["discussion"]["profile"],
        "discussion"
    );
    assert_eq!(
        op.payload["object"]["tracks"]["discussion"]["is_primary"],
        true
    );
    assert_eq!(op.payload["object"]["metadata"]["title"], "Ops");
    assert!(op.payload["object"].get("title").is_none());
    assert_registered_payload_valid(&op);
    assert!(op.payload["object"].get("kind").is_none());
}

#[test]
fn strand_tracks_update_primary_uses_is_primary_patch_key() {
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000001";
    let op = ck_ops::strand_tracks_update_set_primary(
        "ck:realm:0196419b-0000-7000-8000-000000000010",
        "did:web:alice.example",
        strand_id,
        "discussion",
    )
    .expect("builds")
    .build("node");
    assert_eq!(op.kind.as_str(), "ck.strand.tracks.update");
    assert_eq!(
        op.payload["patch"]["tracks.discussion.is_primary"]["value"],
        true
    );
    assert!(
        op.payload["patch"]
            .get("tracks.discussion.primary")
            .is_none()
    );
}

#[test]
fn strand_update_patch_uses_canonical_payload_patch() {
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000002";
    let op = ck_ops::strand_update_patch(
        "ck:realm:0196419b-0000-7000-8000-000000000010",
        "did:web:alice.example",
        strand_id,
        json!({
            "title": { "$op": "set", "value": "Launch checklist" },
            "fields.due_at": { "$op": "set", "value": "2026-05-20" },
        }),
    )
    .expect("builds")
    .build("node");
    assert_eq!(op.kind.as_str(), "ck.strand.update");
    assert_eq!(op.local_target_ref(), Some(strand_id));
    assert_eq!(op.payload["target_ref"], strand_id);
    assert!(op.payload.get("strand_id").is_none());
    assert_eq!(op.payload["patch"]["title"]["value"], "Launch checklist");
    assert!(op.payload.get("fields").is_none());
}

#[test]
fn strand_update_builders_match_registered_object_patch_schema() {
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let actor = "did:web:alice.example";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000002";
    let board_space_id = "ck:space:0196419b-0000-7000-8000-000000000010";
    let list_space_id = "ck:space:0196419b-0000-7000-8000-000000000011";

    let events = [
        ck_ops::strand_update_patch(
            realm_id,
            actor,
            strand_id,
            json!({
                "title": { "$op": "set", "value": "Launch checklist" },
                "fields.due_at": { "$op": "set", "value": "2026-05-20" },
            }),
        )
        .expect("builds")
        .build("node"),
        ck_ops::strand_position_update(
            realm_id,
            actor,
            strand_id,
            json!({
                "strand_id": strand_id,
                "board_space_id": board_space_id,
                "list_space_id": list_space_id,
                "rank": "U",
            }),
        )
        .expect("builds")
        .build("node"),
    ];

    for event in &events {
        assert_eq!(event.kind.as_str(), "ck.strand.update");
        assert!(event.payload.get("patch").is_some());
        assert_eq!(event.payload["target_ref"], strand_id);
        assert!(event.payload.get("strand_id").is_none());
        assert!(event.payload.get("fields").is_none());
        assert!(event.payload.get("position").is_none());
        assert!(event.payload.get("board_space_id").is_none());
        assert!(event.payload.get("expected_position").is_none());
        assert_registered_payload_valid(event);
    }
}

#[test]
fn strand_position_cas_update_rejects_incomplete_effect_position() {
    let error = ck_ops::strand_position_cas_update(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        "ck.strand.move",
        "ck:space:0196419b-0000-7000-8000-000000000010",
        "ck:strand:0196419b-0000-7000-8000-000000000020",
        json!({
            "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000030",
            "rank": "a1"
        }),
        Value::Null,
    )
    .expect_err("missing effect position fields are rejected");

    assert!(
        error
            .to_string()
            .contains("requires effect_position.space_id"),
        "{error:#}"
    );
}

#[test]
fn object_patch_family_builders_match_registered_payload_schema() {
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let actor = "did:web:alice.example";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000002";
    let morph_id = "ck:morph:0196419b-0000-7000-8000-000000000003";
    let space_id = "ck:space:0196419b-0000-7000-8000-000000000004";

    let events = [
        ck_ops::strand_tracks_update_set_primary(realm_id, actor, strand_id, "discussion")
            .expect("builds")
            .build("node"),
        ck_ops::morph_update_patch(
            realm_id,
            actor,
            morph_id,
            json!({ "title": { "$op": "set", "value": "Spec note" } }),
        )
        .expect("builds")
        .build("node"),
        ck_ops::realm_update_patch(
            realm_id,
            actor,
            realm_id,
            json!({ "title": { "$op": "set", "value": "Engineering" } }),
        )
        .expect("builds")
        .build("node"),
        ck_ops::space_update_patch(
            realm_id,
            actor,
            space_id,
            json!({ "title": "Roadmap Board", "summary": "Q2 planning" }),
        )
        .expect("builds")
        .build("node"),
    ];

    for event in &events {
        assert!(event.payload.get("patch").is_some(), "{}", event.kind);
        if event.kind == "ck.strand.tracks.update" {
            assert_eq!(event.payload["strand_id"], strand_id);
            assert!(event.payload.get("target_ref").is_none(), "{}", event.kind);
        } else if event.kind == "ck.space.update" {
            assert_eq!(event.payload["space_id"], space_id);
            assert!(event.payload.get("target_ref").is_none(), "{}", event.kind);
        } else {
            assert!(event.payload.get("target_ref").is_some(), "{}", event.kind);
        }
        assert_registered_payload_valid(event);
    }
}

#[test]
fn strand_position_cas_update_emits_canonical_move_payload() {
    let op = ck_ops::strand_position_cas_update(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        "ck.strand.move",
        "ck:space:0196419b-0000-7000-8000-000000000010",
        "ck:strand:0196419b-0000-7000-8000-000000000020",
        json!({
            "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000030",
            "rank": "a1"
        }),
        json!({
            "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000040",
            "rank": "b1"
        }),
    )
    .expect("builds")
    .build("node");

    assert_eq!(op.kind.as_str(), "ck.strand.move");
    assert_eq!(
        op.payload["board_space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000010"
    );
    assert_eq!(
        op.payload["target_space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000040"
    );
    assert_eq!(op.payload["rank"], "b1");
    assert_eq!(
        op.payload["expected_position"]["space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000030"
    );
    assert_eq!(op.payload["expected_position"]["rank"], "a1");
    assert!(op.payload.get("position").is_none());
}

#[test]
fn strand_position_cas_update_emits_canonical_reorder_payload() {
    let op = ck_ops::strand_position_cas_update(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        "ck.strand.reorder",
        "ck:space:0196419b-0000-7000-8000-000000000010",
        "ck:strand:0196419b-0000-7000-8000-000000000020",
        json!({
            "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000030",
            "rank": "a1"
        }),
        json!({
            "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000030",
            "rank": "a2"
        }),
    )
    .expect("builds")
    .build("node");

    assert_eq!(op.kind.as_str(), "ck.strand.reorder");
    assert_eq!(
        op.payload["board_space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000010"
    );
    assert_eq!(
        op.payload["space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000030"
    );
    assert_eq!(op.payload["rank"], "a2");
    assert_eq!(op.payload["expected_position"]["rank"], "a1");
    assert!(op.payload["expected_position"].get("space_id").is_none());
    assert!(op.payload.get("target_space_id").is_none());
    assert!(op.payload.get("position").is_none());
}

#[test]
fn space_create_emits_canonical_space_object() {
    let op = ck_ops::space_create(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        "ck:space:0196419b-0000-7000-8000-000000000002",
        "list",
        "To Do",
        Some("ck:space:0196419b-0000-7000-8000-000000000003"),
        Some("U"),
    )
    .expect("builds")
    .build("node");
    assert_eq!(op.kind.as_str(), "ck.space.create");
    assert_eq!(
        op.local_target_ref(),
        Some("ck:space:0196419b-0000-7000-8000-000000000002")
    );
    assert_eq!(op.payload["object"]["schema"], "ck.schema.space.v1");
    assert_eq!(
        op.payload["object"]["id"],
        "ck:space:0196419b-0000-7000-8000-000000000002"
    );
    assert_eq!(
        op.payload["object"]["realm_id"],
        "ck:realm:0196419b-0000-7000-8000-000000000001"
    );
    assert!(op.payload["object"].get("space_id").is_none());
    assert_eq!(op.payload["object"]["kind"], "list");
    assert_eq!(
        op.payload["object"]["parent_space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000003"
    );
    assert_eq!(op.payload["object"]["rank"], "U");
    assert_eq!(op.payload["object"]["created_by"], "did:web:alice");
    let created_at = op.payload["object"]["created_at"].as_str().unwrap();
    assert_eq!(created_at.len(), 20);
    assert!(created_at.ends_with('Z'));
    assert!(!created_at.contains('.'));
}

#[test]
fn canonical_digest_is_stable_across_key_order() {
    let mut op_a = OperationBuilder::new(
        "ck:realm:0196419b-0000-7000-8000-0000000000ab",
        "did:web:alice",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"b": 2, "a": 1}))
    .build("node");
    op_a.event_id =
        cokret_sdk::EventId::new("ck:event:0196419b-0000-7000-8000-0000000000ff").unwrap();
    op_a.hlc = cokret_sdk::Hlc::new("000000000000-0000-00000000".to_owned()).unwrap();
    op_a.actor_seq = 1;

    let mut op_b = op_a.clone();
    op_b.payload = json!({"a": 1, "b": 2});

    assert_eq!(
        op_a.canonical_digest().unwrap(),
        op_b.canonical_digest().unwrap()
    );
}

#[test]
fn sign_ed25519_attaches_typed_proof() {
    use ed25519_dalek::SigningKey;
    let mut op = OperationBuilder::new(
        "ck:realm:01904100-0000-7000-8000-000000000001",
        "did:web:alice",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"body": "hi"}))
    .build("node");
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    op.sign_ed25519("did:web:alice", "did:web:alice#k1", &signing_key)
        .expect("sign ok");
    let proof = op.proofs.first().expect("proof present");
    assert_eq!(proof.alg, "EdDSA");
    assert_eq!(proof.verification_method, "did:web:alice#device");
    assert!(proof.event_digest.as_str().starts_with("sha256:"));
    // JWS layout: header.. (detached) ..sig — 3 parts separated by '.'.
    assert_eq!(proof.jws.matches('.').count(), 2);
    assert!(op.require_proof().is_ok());
}

#[test]
fn sdk_event_conversion_accepts_unsigned_builder_for_signing() {
    let op = OperationBuilder::new(
        "ck:realm:01904100-0000-7000-8000-000000000001",
        "did:web:alice.example",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"kind": "ck.content.text", "body": "hi"}))
    .build("node");

    let sdk_event = op.clone();

    assert!(sdk_event.proofs.is_empty());
    assert_eq!(sdk_event.kind.as_str(), "ck.message.create");
    assert_eq!(sdk_event.realm_id.as_str(), op.realm_id.as_str());
}

#[test]
fn sdk_submit_event_conversion_preserves_signed_digest() {
    use ed25519_dalek::SigningKey;

    let mut op = OperationBuilder::new(
        "ck:realm:01904100-0000-7000-8000-000000000001",
        "did:web:alice.example",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"kind": "ck.content.text", "body": "hi"}))
    .build("node");
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    op.sign_ed25519(
        "did:web:alice.example",
        "did:web:alice.example#k1",
        &signing_key,
    )
    .expect("sign ok");

    let local_digest = op.canonical_digest().unwrap();
    let sdk_event = op.clone();
    assert_eq!(sdk_event.event_id, op.event_id);
    assert_eq!(sdk_event.event_digest().unwrap().as_str(), local_digest);
    assert_eq!(op.proofs[0].event_digest.as_str(), local_digest);
}

#[test]
fn require_proof_fails_when_unsigned() {
    let mut op = OperationBuilder::new(
        "ck:realm:0196419b-0000-7000-8000-0000000000ab",
        "did:web:alice",
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({"body": "hi"}))
    .build("node");
    op.proofs.clear();
    assert!(op.require_proof().is_err());
}

#[test]
fn invite_helpers_emit_canonical_kinds() {
    let invite_id = "ck:invite:01904100-0000-7000-8000-000000000001";
    let invite_delivery_target = cokret_sdk::InviteDeliveryTarget {
        recipient_service_did: cokret_sdk::Did::new("did:web:server.example").unwrap(),
        recipient_service_type: Some("principal_server".to_owned()),
    };
    let introduction_evidence_digest =
        crate::canonical::canonical_sha256(&json!({"kind": "explicit_address"})).unwrap();
    let create = ck_ops::invite_create_structured(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        invite_id,
        "did:web:bob.example",
        Some("member"),
        invite_delivery_target.clone(),
        &introduction_evidence_digest,
    )
    .expect("builds")
    .build("node");
    assert_eq!(create.kind.as_str(), "ck.invite.create");
    assert_eq!(create.payload["invite_id"], invite_id);
    assert_eq!(create.payload["invitee"], "did:web:bob.example");
    assert_eq!(
        create.payload["invite_delivery_target"],
        serde_json::to_value(invite_delivery_target).unwrap()
    );
    assert_eq!(
        create.payload["introduction_evidence_digest"],
        introduction_evidence_digest
    );
    assert!(
        cokret_sdk::canonical::validate_timestamp_canonical(
            create.payload["expires_at"].as_str().unwrap()
        )
        .is_ok()
    );
    assert_eq!(create.payload["x_role"], "member");
    assert!(
        create
            .payload
            .get("expires_at")
            .and_then(|value| value.as_str())
            .is_some()
    );
    assert!(create.payload.get("target").is_none());
    assert!(create.payload.get("role").is_none());
    assert!(create.payload.get("state").is_none());
    assert!(create.payload.get("x_member_delivery_binding").is_none());
    assert_registered_payload_valid(&create);

    let accept = ck_ops::invite_accept(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:bob.example",
        invite_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(accept.kind.as_str(), "ck.invite.accept");
    assert_eq!(accept.payload["invite_id"], invite_id);
    assert!(accept.payload.get("state").is_none());
    assert_registered_payload_valid(&accept);

    let cancel = ck_ops::invite_cancel(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        invite_id,
        Some("expired"),
    )
    .expect("builds")
    .build("node");
    assert_eq!(cancel.kind.as_str(), "ck.invite.cancel");
    assert_eq!(cancel.payload["invite_id"], invite_id);
    assert_eq!(cancel.payload["reason"], "expired");
    assert!(cancel.payload.get("state").is_none());
    assert_registered_payload_valid(&cancel);
}

#[test]
fn space_lifecycle_helpers_emit_canonical_kinds() {
    let container_space_id = "ck:space:01904100-0000-7000-8000-1fb50799ad42";
    let archive = ck_ops::realm_archive(
        "ck:realm:01904100-0000-7000-8000-1fb50799ad40",
        "did:web:alice.example",
        container_space_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(archive.kind.as_str(), "ck.space.archive");
    assert_eq!(archive.payload["space_id"], container_space_id);
    assert_eq!(archive.local_target_ref(), Some(container_space_id));

    let restore = ck_ops::space_restore(
        "ck:realm:01904100-0000-7000-8000-1fb50799ad40",
        "did:web:alice.example",
        container_space_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(restore.kind.as_str(), "ck.space.restore");
    assert_eq!(restore.payload["space_id"], container_space_id);
    assert_eq!(restore.local_target_ref(), Some(container_space_id));
}

#[test]
fn strand_lifecycle_helpers_emit_canonical_kinds() {
    let strand_id = "ck:strand:01904100-0000-7000-8000-1fb50799ad50";
    let archive = ck_ops::strand_archive(
        "ck:realm:0196419b-0000-7000-8000-0000000000aa",
        "did:web:alice.example",
        strand_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(archive.kind.as_str(), "ck.strand.archive");
    assert_eq!(archive.payload["target_ref"], strand_id);
    assert!(archive.payload.get("strand_id").is_none());
    assert_eq!(archive.local_target_ref(), Some(strand_id));
    assert_registered_payload_valid(&archive);

    let restore = ck_ops::strand_restore(
        "ck:realm:0196419b-0000-7000-8000-0000000000aa",
        "did:web:alice.example",
        strand_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(restore.kind.as_str(), "ck.strand.restore");
    assert_eq!(restore.payload["target_ref"], strand_id);
    assert!(restore.payload.get("strand_id").is_none());
    assert_eq!(restore.local_target_ref(), Some(strand_id));
    assert_registered_payload_valid(&restore);
}

/// Pin the canonical op_type + target_ref + body shape for every
/// `ck.applet.*` builder so server-side validators (soland operation
/// requirements) keep accepting them.
#[test]
fn applet_helpers_emit_canonical_kinds_and_target_refs() {
    let service_did = "did:web:applet.example";
    let session_id = "ck:session:01904100-0000-7000-8000-aa55aa55aa55";
    let applet_id = "did:web:applet.example";
    let realm = "ck:realm:0196419b-0000-7000-8000-0000000000aa";
    let actor = "did:web:alice.example";

    let reg = ck_ops::applet_registration(realm, actor, service_did, "extensions", &["read"])
        .build("node");
    assert_eq!(reg.kind.as_str(), "ck.applet.registration");
    assert_eq!(reg.payload["service_did"], service_did);
    assert_eq!(reg.payload["namespace"], "extensions");
    assert_eq!(reg.payload["capabilities"][0], "read");
    assert_eq!(reg.local_target_ref(), Some(service_did));

    let disc =
        ck_ops::applet_discovery(realm, actor, service_did, json!({"version": 1})).build("node");
    assert_eq!(disc.kind.as_str(), "ck.applet.discovery");
    assert_eq!(disc.payload["manifest"]["version"], 1);
    assert_eq!(disc.local_target_ref(), Some(service_did));

    let start = ck_ops::applet_interop_session_start(
        realm,
        actor,
        applet_id,
        session_id,
        json!({"op": "ping"}),
    )
    .expect("builds")
    .build("node");
    assert_eq!(start.kind.as_str(), "ck.applet.interop_session.start");
    assert_eq!(start.payload["applet_id"], applet_id);
    assert_eq!(start.payload["session_id"], session_id);
    assert_eq!(start.local_target_ref(), Some(session_id));
    assert_registered_payload_valid(&start);

    let status = ck_ops::applet_interop_session_status(
        realm,
        actor,
        applet_id,
        session_id,
        "running",
        json!({"progress_basis_points": 5000}),
    )
    .expect("builds")
    .build("node");
    assert_eq!(status.kind.as_str(), "ck.applet.interop_session.status");
    assert_eq!(status.payload["applet_id"], applet_id);
    assert_eq!(status.payload["runtime_status"], "running");
    assert!(status.payload.get("status").is_none());
    assert_registered_payload_valid(&status);

    let err = ck_ops::applet_bridge_error(
        realm,
        actor,
        applet_id,
        "ck:event:01904100-0000-7000-8000-aa55aa55aa56",
        "external_network",
        "applet_unavailable",
        true,
        "realm_admins",
        "service did not respond",
    )
    .expect("builds")
    .build("node");
    assert_eq!(err.kind.as_str(), "ck.applet.bridge_error");
    assert_eq!(err.payload["applet_id"], applet_id);
    assert_eq!(
        err.payload["failed_transaction_ref"],
        "ck:event:01904100-0000-7000-8000-aa55aa55aa56"
    );
    assert_eq!(err.payload["error_class"], "external_network");
    assert_eq!(err.payload["error_code"], "applet_unavailable");
    assert!(err.payload.get("session_id").is_none());
    assert_registered_payload_valid(&err);
}

/// Same pinning at the agent layer.
#[test]
fn agent_helpers_emit_canonical_kinds_and_target_refs() {
    let agent = "did:web:researcher.agent.example";
    let session_id = "ck:agent_interop_session:01904100-0000-7000-8000-bb66bb66bb66";
    let realm = "ck:realm:0196419b-0000-7000-8000-0000000000aa";
    let actor = "did:web:alice.example";

    let endpoint = ck_ops::agent_endpoint(realm, actor, agent, "ck.agent.v1", &["strand.read"])
        .expect("builds")
        .build("node");
    assert_eq!(endpoint.kind.as_str(), "ck.agent.endpoint");
    assert_eq!(endpoint.payload["endpoints"][0]["protocol"], "ck.agent.v1");
    assert_eq!(endpoint.local_target_ref(), Some(agent));

    let start = ck_ops::agent_interop_session_start(
        realm,
        actor,
        agent,
        session_id,
        "http_custom",
        json!({"query": "summarize"}),
        "ck:grant:01904100-0000-7000-8000-000000000099",
    )
    .expect("builds")
    .build("node");
    assert_eq!(start.kind.as_str(), "ck.agent.interop_session.start");
    assert_eq!(start.payload["counterparty_agent"], agent);
    assert_eq!(
        start.payload["capability_grant"],
        "ck:grant:01904100-0000-7000-8000-000000000099"
    );
    assert!(start.payload.get("params").is_none());
    assert_registered_payload_valid(&start);

    let status =
        ck_ops::agent_interop_session_status(realm, actor, session_id, "working", json!({}))
            .expect("builds")
            .build("node");
    assert_eq!(status.kind.as_str(), "ck.agent.interop_session.status");
    assert_eq!(status.payload["status"], "working");
    assert!(status.payload.get("detail").is_none());
    assert_registered_payload_valid(&status);

    let result = ck_ops::agent_interop_session_result(
        realm,
        actor,
        session_id,
        json!({"summary": "TL;DR"}),
        json!({"merkle_root": "sha256:abc"}),
    )
    .expect("builds")
    .build("node");
    assert_eq!(result.kind.as_str(), "ck.agent.interop_session.result");
    assert_eq!(result.payload["status"], "completed");
    assert_eq!(result.payload["result_objects"][0]["summary"], "TL;DR");
    assert_eq!(result.payload["artifacts"][0]["merkle_root"], "sha256:abc");
    assert!(result.payload.get("result").is_none());
    assert!(result.payload.get("audit_binding").is_none());
    assert_registered_payload_valid(&result);
}

#[test]
fn message_revise_builder_uses_content_payload_schema() {
    let message_id = "ck:message:01904100-0000-7000-8000-000000000123";
    let event = ck_ops::message_revise_content(
        "ck:realm:0196419b-0000-7000-8000-0000000000aa",
        "did:web:alice.example",
        message_id,
        cokret_sdk::ContentBlock::text("updated body"),
    )
    .expect("builds")
    .build("node");

    assert_eq!(event.kind.as_str(), "ck.message.revise");
    assert_eq!(event.payload["message_id"], message_id);
    assert_eq!(event.payload["content"]["kind"], "ck.content.text");
    assert_eq!(event.payload["content"]["body"], "updated body");
    assert!(event.payload.get("patch").is_none());
    assert_registered_payload_valid(&event);
}

// ── YGN-ORG-05 — ck.realm.organization builder snapshot + negative tests ──
//
// Covers the YGN-ORG-02 builder: active / revoked payload snapshots against
// the registered spec schema, plus negative coverage for missing delegation,
// missing proof, and the status / revocation coupling. These are the
// client-side counterparts of the SDK statement verifier tests; the helper
// produces real `ck.realm.organization` events that cotest can reuse.
mod realm_organization_builder_tests {
    use chrono::TimeZone;
    use cokret_sdk::models::{
        RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
        RealmOrganizationStatus, SignatureMaterial,
    };

    use super::*;
    use crate::operation::ck_ops::RealmOrganizationAuthorizationInput;

    const REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000010";
    const ACTOR: &str = "did:web:alice.example";
    const ORG_DID: &str = "did:webvh:example.test:orgs:org1";
    const ORG_VM: &str = "did:webvh:example.test:orgs:org1#k1";

    fn signed_at() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn direct_org_auth() -> RealmOrganizationAuthorizationInput {
        // OrganizationDid is a non-delegated role: no delegation_ref.
        RealmOrganizationAuthorizationInput {
            issuer: ORG_DID.to_owned(),
            issuer_role: RealmOrganizationIssuerRole::OrganizationDid,
            verification_method: ORG_VM.to_owned(),
            delegation_ref: None,
            executed_by: Some("did:web:admin.example".to_owned()),
            signed_at: signed_at(),
            proof: SignatureMaterial::NonEmptyString("c2ln".to_owned()),
        }
    }

    fn delegated_org_auth() -> RealmOrganizationAuthorizationInput {
        RealmOrganizationAuthorizationInput {
            issuer: "did:web:gov.example".to_owned(),
            issuer_role: RealmOrganizationIssuerRole::GovernanceService,
            verification_method: "did:web:gov.example#k1".to_owned(),
            delegation_ref: Some("ck:grant:01904100-0000-7000-8000-000000000001".to_owned()),
            executed_by: None,
            signed_at: signed_at(),
            proof: SignatureMaterial::NonEmptyString("c2ln".to_owned()),
        }
    }

    #[test]
    fn active_statement_matches_registered_payload_schema() {
        let event = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-1",
            ORG_DID,
            RealmOrganizationRelationship::Owner,
            RealmOrganizationStatus::Active,
            vec![
                RealmOrganizationControlScope::OfficialBadge,
                RealmOrganizationControlScope::RealmAdmin,
            ],
            signed_at(),
            direct_org_auth(),
            None,
        )
        .expect("builds")
        .build("node");

        assert_eq!(event.kind.as_str(), "ck.realm.organization");
        // The statement binds the organization DID, not a Space/Strand id.
        assert_eq!(event.local_target_ref(), Some(ORG_DID));
        assert_eq!(event.payload["organization_id"], ORG_DID);
        assert_eq!(event.payload["relationship"], "owner");
        assert_eq!(event.payload["status"], "active");
        assert!(event.payload.get("revokes_statement_id").is_none());
        // The organization proof is carried verbatim, not synthesized from the
        // local login session.
        assert_eq!(
            event.payload["authorization"]["issuer_role"],
            "organization_did"
        );
        assert_eq!(event.payload["authorization"]["proof"], "c2ln");
        assert_payload_field_names_are_spec_canonical(&event.payload);
        assert_registered_payload_valid(&event);
    }

    #[test]
    fn delegated_active_statement_carries_delegation_ref() {
        let event = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-gov",
            ORG_DID,
            RealmOrganizationRelationship::Governance,
            RealmOrganizationStatus::Active,
            vec![RealmOrganizationControlScope::ModerationPolicy],
            signed_at(),
            delegated_org_auth(),
            None,
        )
        .expect("builds")
        .build("node");

        assert_eq!(event.payload["relationship"], "governance");
        assert_eq!(
            event.payload["authorization"]["issuer_role"],
            "governance_service"
        );
        assert_eq!(
            event.payload["authorization"]["delegation_ref"],
            "ck:grant:01904100-0000-7000-8000-000000000001"
        );
        assert_registered_payload_valid(&event);
    }

    #[test]
    fn revoked_statement_matches_registered_payload_schema() {
        let event = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-2",
            ORG_DID,
            RealmOrganizationRelationship::Owner,
            RealmOrganizationStatus::Revoked,
            vec![RealmOrganizationControlScope::OfficialBadge],
            signed_at(),
            direct_org_auth(),
            Some("org-stmt-1".to_owned()),
        )
        .expect("builds")
        .build("node");

        assert_eq!(event.payload["status"], "revoked");
        assert_eq!(event.payload["revokes_statement_id"], "org-stmt-1");
        assert_registered_payload_valid(&event);
    }

    #[test]
    fn revoked_without_revokes_statement_id_is_rejected() {
        let error = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-3",
            ORG_DID,
            RealmOrganizationRelationship::Owner,
            RealmOrganizationStatus::Revoked,
            vec![RealmOrganizationControlScope::OfficialBadge],
            signed_at(),
            direct_org_auth(),
            None,
        )
        .expect_err("revoked must require revokes_statement_id");
        assert!(
            error.to_string().contains("revokes_statement_id"),
            "{error:#}"
        );
    }

    #[test]
    fn active_with_revokes_statement_id_is_rejected() {
        let error = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-4",
            ORG_DID,
            RealmOrganizationRelationship::Owner,
            RealmOrganizationStatus::Active,
            vec![RealmOrganizationControlScope::OfficialBadge],
            signed_at(),
            direct_org_auth(),
            Some("org-stmt-1".to_owned()),
        )
        .expect_err("active must not carry revokes_statement_id");
        assert!(
            error.to_string().contains("revokes_statement_id"),
            "{error:#}"
        );
    }

    #[test]
    fn delegated_role_without_delegation_ref_is_rejected() {
        let mut auth = delegated_org_auth();
        auth.delegation_ref = None;
        let error = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-5",
            ORG_DID,
            RealmOrganizationRelationship::Governance,
            RealmOrganizationStatus::Active,
            vec![RealmOrganizationControlScope::ModerationPolicy],
            signed_at(),
            auth,
            None,
        )
        .expect_err("delegated role must carry delegation_ref");
        assert!(error.to_string().contains("delegation_ref"), "{error:#}");
    }

    #[test]
    fn non_delegated_role_with_delegation_ref_is_rejected() {
        let mut auth = direct_org_auth();
        auth.delegation_ref = Some("ck:grant:01904100-0000-7000-8000-000000000001".to_owned());
        let error = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-6",
            ORG_DID,
            RealmOrganizationRelationship::Owner,
            RealmOrganizationStatus::Active,
            vec![RealmOrganizationControlScope::OfficialBadge],
            signed_at(),
            auth,
            None,
        )
        .expect_err("non-delegated role must not carry delegation_ref");
        assert!(error.to_string().contains("delegation_ref"), "{error:#}");
    }

    #[test]
    fn missing_proof_is_rejected_by_registered_schema() {
        // An empty proof string is structurally invalid; the registered spec
        // schema rejects it. The builder copies the proof verbatim, so this
        // guards that a missing/empty organization proof can never ship.
        let mut auth = direct_org_auth();
        auth.proof = SignatureMaterial::NonEmptyString(String::new());
        let event = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-7",
            ORG_DID,
            RealmOrganizationRelationship::Owner,
            RealmOrganizationStatus::Active,
            vec![RealmOrganizationControlScope::OfficialBadge],
            signed_at(),
            auth,
            None,
        )
        .expect("builds (schema enforces the empty-proof rejection)")
        .build("node");
        let catalog = cokret_sdk::schema::event_payload_validator_catalog().unwrap();
        assert!(
            catalog
                .validate_payload(event.kind.as_str(), &event.payload)
                .is_err(),
            "empty organization proof must violate the registered schema"
        );
    }

    #[test]
    fn empty_control_scopes_is_rejected() {
        let error = ck_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-8",
            ORG_DID,
            RealmOrganizationRelationship::Owner,
            RealmOrganizationStatus::Active,
            Vec::new(),
            signed_at(),
            direct_org_auth(),
            None,
        )
        .expect_err("control_scopes must not be empty");
        assert!(error.to_string().contains("control_scopes"), "{error:#}");
    }
}
