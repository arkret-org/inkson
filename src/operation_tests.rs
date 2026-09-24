use serde_json::{Value, json};

use super::*;

fn message_builder(realm_id: &str, actor_id: &str, body: &str) -> TypedOperationBuilder {
    TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
        realm_id,
        actor_id,
        arkret_sdk::MessageCreatePayload::with_content(
            arkret_sdk::StrandId::new(
                "ak:strand:AXA352XtBodUhnMN_nDxOloEHVn0_yAotxiYxbyU38Df".to_owned(),
            )
            .unwrap(),
            "discussion",
            arkret_sdk::ContentBlock::text(body),
        ),
    )
}

fn assert_registered_payload_valid(operation: &LocalOperation) {
    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    let payload = serde_json::to_value(operation.payload()).unwrap();
    catalog
        .validate_payload(operation.kind().as_str(), &payload)
        .unwrap_or_else(|err| {
            panic!(
                "{} payload violates registered spec schema: {err}\npayload: {}",
                operation.kind(),
                serde_json::to_string_pretty(operation.payload()).unwrap()
            );
        });
}

/// Finalize a built write so a test can inspect the envelope that ships.
fn authored(operation: &LocalOperation) -> arkret_sdk::AuthoredEvent {
    author_for_test(operation)
}

fn assert_payload_field_names_are_spec_canonical(
    payload: &std::collections::BTreeMap<String, serde_json::Value>,
) {
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
    let value = serde_json::to_value(payload).unwrap();
    check(&value).unwrap_or_else(|err| {
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
    let op = message_builder(
        "ak:realm:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
        "did:web:alice",
        "hello",
    )
    .build("test_node");

    assert!(!op.local_operation_id().as_str().is_empty());
    assert_eq!(
        op.realm_id_opt().expect("realm-scoped write").as_str(),
        "ak:realm:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8"
    );
    assert_eq!(
        op.actor_id().signing_principal_id().as_str(),
        "ak:did_core:web:alice"
    );
    assert_eq!(op.kind().as_str(), "ak.message.create");

    // The content-bound identity arrives at the finalize boundary, and
    // nothing carries a proof before a producer identity exists.
    let event = authored(&op);
    assert!(!event.event_id().as_str().is_empty());
    assert!(event.producer_proof.is_none());
    event.verify_identity().unwrap();
}

#[test]
fn operation_builder_delegates_event_time_normalization_to_the_sdk() {
    let op = message_builder(
        "ak:realm:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
        "did:web:alice",
        "hello",
    )
    .created_at("2026-07-18T10:20:30.987654Z".parse().unwrap())
    .build_sdk_event("test_node")
    .unwrap();

    assert_eq!(
        op.intent()
            .created_at()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "2026-07-18T10:20:30.987Z"
    );
}

#[test]
fn operation_round_trip_serde() {
    let op = message_builder(
        "ak:realm:Ac3EwB_awdKZ0dXZDsjIRnTX_zdhqT84eUG5NXqUbg0f",
        "did:web:bob",
        "hello world",
    )
    .build("node");
    // Deserializing re-derives the identity from the content it reads, so a
    // round trip is also a proof that the two agree.
    let event = authored(&op);
    let json = serde_json::to_string(&event).unwrap();
    let parsed: arkret_sdk::AuthoredEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

#[test]
fn operation_builder_can_emit_signed_authorization_binding() {
    let op = message_builder(
        "ak:realm:Ac3EwB_awdKZ0dXZDsjIRnTX_zdhqT84eUG5NXqUbg0f",
        "did:web:bob",
        "hello world",
    )
    .executed_by("did:web:agent.example")
    .authorization_ref("ak:grant:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS")
    .build("node");

    assert_eq!(
        op.intent()
            .executed_by()
            .as_ref()
            .map(|actor| actor.signing_principal_id().as_str()),
        Some("ak:did_core:web:agent.example")
    );
    assert_eq!(
        op.intent()
            .authorization_ref()
            .map(arkret_sdk::AuthorizationRef::as_str),
        Some("ak:grant:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS")
    );

    let event = authored(&op);
    let mut canonical = serde_json::to_value(event.event()).unwrap();
    assert!(canonical.get("unsigned").is_none());
    if let serde_json::Value::Object(object) = &mut canonical {
        object.remove("producer_proof");
    }
    assert_eq!(
        canonical["executed_by"],
        json!({"kind": "account", "account_id": {
            "principal_id": "ak:did_core:web:agent.example",
            "station_id": "ak:did_core:web:principal.example"
        }})
    );
    assert_eq!(
        canonical["authorization_ref"],
        "ak:grant:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS"
    );
}

#[test]
fn event_envelope_accepts_current_optional_top_level_fields_and_rejects_removed_actor_kind() {
    let op = message_builder(
        "ak:realm:Ac3EwB_awdKZ0dXZDsjIRnTX_zdhqT84eUG5NXqUbg0f",
        "did:web:bob",
        "hello world",
    )
    .build("node");
    let authored = authored(&op);
    let mut value = serde_json::to_value(authored.event()).unwrap();
    // The top-level `effective_scope` field is deleted in v1; a wire object
    // that still carries it MUST be rejected rather than silently ignored.
    let mut with_stale_field = value.clone();
    with_stale_field.as_object_mut().unwrap().insert(
        "effective_scope".to_owned(),
        json!({"kind": "realm", "realm_id": "ak:realm:Ac3EwB_awdKZ0dXZDsjIRnTX_zdhqT84eUG5NXqUbg0f"}),
    );
    assert!(serde_json::from_value::<Event>(with_stale_field).is_err());
    let object = value.as_object_mut().unwrap();
    object.insert(
        "executed_by".to_owned(),
        json!({"kind": "account", "account_id": {
            "principal_id": "ak:did_core:web:agent.example",
            "station_id": "ak:did_core:web:principal.example"
        }}),
    );
    object.insert(
        "authorization_ref".to_owned(),
        json!("ak:grant:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS"),
    );
    let parsed: Event = serde_json::from_value(value.clone()).unwrap();
    // `scope_ref` is a REQUIRED producer-signed field in v1 (the wire has no
    // reducer-stamped `effective_scope` any more), and the envelope `realm_id`
    // is derived from it.
    assert_eq!(
        parsed.scope_ref,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:Ac3EwB_awdKZ0dXZDsjIRnTX_zdhqT84eUG5NXqUbg0f".to_owned()
            )
            .unwrap(),
        }
    );
    assert_eq!(
        parsed
            .executed_by
            .as_ref()
            .map(|actor| actor.signing_principal_id().as_str()),
        Some("ak:did_core:web:agent.example")
    );
    assert_eq!(
        parsed.authorization_ref.as_deref(),
        Some("ak:grant:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS")
    );
    value
        .as_object_mut()
        .unwrap()
        .insert("actor_kind".to_owned(), json!("agent"));
    assert!(serde_json::from_value::<Event>(value).is_err());
}

#[test]
fn event_envelope_rejects_unknown_top_level_fields() {
    let op = message_builder(
        "ak:realm:Ac3EwB_awdKZ0dXZDsjIRnTX_zdhqT84eUG5NXqUbg0f",
        "did:web:bob",
        "hello world",
    )
    .build("node");
    let authored = authored(&op);
    let mut value = serde_json::to_value(authored.event()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("sender".to_owned(), json!("did:web:removed.example"));

    assert!(
        serde_json::from_value::<Event>(value).is_err(),
        "deprecated/unknown top-level envelope fields must fail closed"
    );
}

#[test]
fn kanban_card_strand_create_omits_position_metadata() {
    let op = ak_ops::kanban_card_strand_create(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice.example",
        "Move-backed card",
    )
    .expect("builds")
    .build("node");

    assert_eq!(op.kind().as_str(), "ak.strand.create");
    assert_eq!(
        op.realm_id_opt().expect("realm-scoped write").as_str(),
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(
        op.payload()["object"]["realm_id"],
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(
        op.payload()["object"]["tracks"]["synthesis"]["profile"],
        "kanban_card"
    );
    assert_eq!(
        op.payload()["object"]["tracks"]["discussion"]["profile"],
        "discussion"
    );
    assert!(op.payload()["object"].get("stage").is_none());
    assert!(
        op.payload()["object"]["metadata"]["fields"]
            .get("board_space_id")
            .is_none()
    );
    assert!(
        op.payload()["object"]["metadata"]["fields"]
            .get("list_space_id")
            .is_none()
    );
    assert!(
        op.payload()["object"]["metadata"]["fields"]
            .get("rank")
            .is_none()
    );
    assert_eq!(
        op.payload()["object"]["metadata"]["title"],
        "Move-backed card"
    );
    assert!(op.payload()["object"].get("fields").is_none());
    assert!(op.payload()["object"].get("title").is_none());
    assert!(op.payload()["object"].get("space_id").is_none());
    assert!(!op.payload().contains_key("components"));
    assert!(!op.payload().contains_key("patch"));
    assert_registered_payload_valid(&op);
    assert_payload_field_names_are_spec_canonical(op.payload());
}

#[test]
fn mls_commit_builder_matches_registered_payload_schema() {
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let base_group_state_ref =
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x22; 32]);
    let governance_binding = arkret_sdk::MlsGovernanceBindingPayload::realm(
        arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
        Some(base_group_state_ref.clone()),
        0,
        1,
        0,
    )
    .unwrap();
    let commit_bytes = b"operation-test-commit";
    let commit = arkret_sdk::MlsCommitEnvelope {
        group_id: governance_binding.mls_group_id().unwrap(),
        epoch: 1,
        commit: arkret_sdk::base64url_encode(commit_bytes),
        commit_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(commit_bytes))
            .unwrap(),
        ratchet_tree: None,
    };
    let payload =
        arkret_sdk::MlsCommitPayload::new(base_group_state_ref, 0, &commit, governance_binding)
            .unwrap();
    let op = ak_ops::mls_commit_with_governance(realm_id, "did:web:alice.example", &payload)
        .unwrap()
        .build("node");

    assert_eq!(op.kind().as_str(), "ak.mls.commit");
    assert!(!op.payload().contains_key("group_id"));
    assert!(!op.payload().contains_key("preconditions"));
    assert!(!op.payload().contains_key("effects"));
    assert_registered_payload_valid(&op);
    assert_payload_field_names_are_spec_canonical(op.payload());
}

#[test]
fn discussion_strand_create_emits_discussion_track() {
    let op = ak_ops::discussion_strand_create(
        "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk",
        "did:web:alice.example",
        "Ops",
        "general",
        None,
        None,
        false,
    )
    .unwrap()
    .build("node");
    assert_eq!(op.kind().as_str(), "ak.strand.create");
    // The create payload carries no object id, and neither does the write: the
    // Strand is named by `retype(event_id)` of the create, which does not exist
    // until the create is finalized.
    assert!(op.payload()["object"].get("id").is_none());
    assert_eq!(op.local_target_ref(), None);
    let event = authored(&op);
    assert_eq!(
        arkret_sdk::StrandId::from_event_id(event.event_id()).token_bytes(),
        event.event_id().token_bytes()
    );
    assert!(!op.payload().contains_key("strand_id"));
    assert_eq!(
        op.payload()["object"]["tracks"]["discussion"]["profile"],
        "discussion"
    );
    assert_eq!(
        op.payload()["object"]["tracks"]["discussion"]["is_primary"],
        true
    );
    assert_eq!(op.payload()["object"]["metadata"]["title"], "Ops");
    assert!(op.payload()["object"].get("title").is_none());
    assert!(op.payload()["object"].get("stage").is_none());
    // `metadata.fields.rank` is a forbidden Strand member; placement lives in
    // the position component written by move / reorder.
    assert!(
        op.payload()["object"]["metadata"]["fields"]
            .get("rank")
            .is_none()
    );
    assert_registered_payload_valid(&op);
    assert!(op.payload()["object"].get("kind").is_none());
}

#[test]
fn strand_tracks_update_primary_uses_is_primary_patch_key() {
    let strand_id = "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let op = ak_ops::strand_tracks_update_set_primary(
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        "did:web:alice.example",
        strand_id,
        "discussion",
    )
    .expect("builds")
    .build("node");
    assert_eq!(op.kind().as_str(), "ak.strand.tracks.update");
    assert_eq!(
        op.payload()["patch"]["tracks.discussion.is_primary"]["value"],
        true
    );
    assert!(
        op.payload()["patch"]
            .get("tracks.discussion.primary")
            .is_none()
    );
}

#[test]
fn strand_update_patch_uses_canonical_payload_patch() {
    let strand_id = "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let op = ak_ops::strand_update_patch(
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        "did:web:alice.example",
        strand_id,
        json!({
            "title": { "$op": "set", "value": "Launch checklist" },
            "fields.due_at": { "$op": "set", "value": "2026-05-20" },
        }),
    )
    .expect("builds")
    .build("node");
    assert_eq!(op.kind().as_str(), "ak.strand.update");
    assert_eq!(op.local_target_ref(), Some(strand_id));
    assert_eq!(op.payload()["target_ref"], strand_id);
    assert!(!op.payload().contains_key("strand_id"));
    assert_eq!(op.payload()["patch"]["title"]["value"], "Launch checklist");
    assert!(!op.payload().contains_key("fields"));
}

#[test]
fn strand_update_builders_match_registered_object_patch_schema() {
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let actor = "did:web:alice.example";
    let strand_id = "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";

    let events = [ak_ops::strand_update_patch(
        realm_id,
        actor,
        strand_id,
        json!({
            "title": { "$op": "set", "value": "Launch checklist" },
            "fields.due_at": { "$op": "set", "value": "2026-05-20" },
        }),
    )
    .expect("builds")
    .build("node")];

    for event in &events {
        assert_eq!(event.kind().as_str(), "ak.strand.update");
        assert!(event.payload().contains_key("patch"));
        assert_eq!(event.payload()["target_ref"], strand_id);
        assert!(!event.payload().contains_key("strand_id"));
        assert!(!event.payload().contains_key("fields"));
        assert!(!event.payload().contains_key("position"));
        assert!(!event.payload().contains_key("board_space_id"));
        assert!(!event.payload().contains_key("expected_position"));
        assert_registered_payload_valid(event);
    }
}

#[test]
fn strand_position_update_rejects_incomplete_effect_position() {
    let error = ak_ops::strand_position_update(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice",
        "ak.strand.move",
        "ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        "ak:strand:AUuXpUO-yBwwyCNB7AS1IIm5_sgsxyEsG7PBmmkXdFog",
        json!({
            "list_space_id": "ak:space:ASnqpJQi0G5Ljanp7UQXjmcIaFVqDSvBNupH4kpQaTzc",
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
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let actor = "did:web:alice.example";
    let strand_id = "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let morph_id = "ak:morph:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let space_id = "ak:space:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K";

    let events = [
        ak_ops::strand_tracks_update_set_primary(realm_id, actor, strand_id, "discussion")
            .expect("builds")
            .build("node"),
        ak_ops::morph_update_patch(
            realm_id,
            actor,
            morph_id,
            json!({ "title": { "$op": "set", "value": "Spec note" } }),
        )
        .expect("builds")
        .build("node"),
        ak_ops::space_update_patch(
            realm_id,
            actor,
            space_id,
            json!({ "title": "Roadmap Board", "summary": "Q2 planning" }),
        )
        .expect("builds")
        .build("node"),
    ];

    for event in &events {
        assert!(event.payload().contains_key("patch"), "{}", event.kind());
        if event.kind() == "ak.space.update" {
            assert_eq!(event.payload()["space_id"], space_id);
            assert!(
                !event.payload().contains_key("target_ref"),
                "{}",
                event.kind()
            );
        } else {
            // Everything else — including `ak.strand.tracks.update` —
            // single-sources the target in the signed payload.
            assert!(
                event.payload().contains_key("target_ref"),
                "{}",
                event.kind()
            );
        }
        assert_registered_payload_valid(event);
    }
}

#[test]
fn strand_position_update_emits_canonical_move_payload() {
    let op = ak_ops::strand_position_update(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice",
        "ak.strand.move",
        "ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        "ak:strand:AUuXpUO-yBwwyCNB7AS1IIm5_sgsxyEsG7PBmmkXdFog",
        json!({
            "list_space_id": "ak:space:ASnqpJQi0G5Ljanp7UQXjmcIaFVqDSvBNupH4kpQaTzc",
            "rank": "a1"
        }),
        json!({
            "list_space_id": "ak:space:AeQLz_7_lGwMdENhkoPlgbKh0MqfZ-5HB8Vz5zWCeClm",
            "rank": "b1"
        }),
    )
    .expect("builds")
    .build("node");

    assert_eq!(op.kind().as_str(), "ak.strand.move");
    assert_eq!(
        op.payload()["board_space_id"],
        "ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo"
    );
    assert_eq!(
        op.payload()["target_space_id"],
        "ak:space:AeQLz_7_lGwMdENhkoPlgbKh0MqfZ-5HB8Vz5zWCeClm"
    );
    assert_eq!(op.payload()["rank"], "b1");
    assert_eq!(
        op.payload()["expected_position"]["space_id"],
        "ak:space:ASnqpJQi0G5Ljanp7UQXjmcIaFVqDSvBNupH4kpQaTzc"
    );
    assert_eq!(op.payload()["expected_position"]["rank"], "a1");
    assert!(!op.payload().contains_key("position"));
}

#[test]
fn strand_position_update_emits_canonical_reorder_payload() {
    let op = ak_ops::strand_position_update(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice",
        "ak.strand.reorder",
        "ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        "ak:strand:AUuXpUO-yBwwyCNB7AS1IIm5_sgsxyEsG7PBmmkXdFog",
        json!({
            "list_space_id": "ak:space:ASnqpJQi0G5Ljanp7UQXjmcIaFVqDSvBNupH4kpQaTzc",
            "rank": "a1"
        }),
        json!({
            "list_space_id": "ak:space:ASnqpJQi0G5Ljanp7UQXjmcIaFVqDSvBNupH4kpQaTzc",
            "rank": "a2"
        }),
    )
    .expect("builds")
    .build("node");

    assert_eq!(op.kind().as_str(), "ak.strand.reorder");
    assert_eq!(
        op.payload()["board_space_id"],
        "ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo"
    );
    assert_eq!(
        op.payload()["space_id"],
        "ak:space:ASnqpJQi0G5Ljanp7UQXjmcIaFVqDSvBNupH4kpQaTzc"
    );
    assert_eq!(op.payload()["rank"], "a2");
    assert_eq!(op.payload()["expected_position"]["rank"], "a1");
    assert!(op.payload()["expected_position"].get("space_id").is_none());
    assert!(!op.payload().contains_key("target_space_id"));
    assert!(!op.payload().contains_key("position"));
}

#[test]
fn space_create_emits_canonical_space_object() {
    let op = ak_ops::space_create(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice",
        "list",
        "To Do",
        Some("ak:space:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2"),
        Some("U"),
    )
    .expect("builds")
    .build("node");
    assert_eq!(op.kind().as_str(), "ak.space.create");
    // The Space is named by this create Event, not chosen by the caller — so the
    // write reports no target and the id appears only once it is finalized.
    assert_eq!(op.local_target_ref(), None);
    let event = authored(&op);
    assert_eq!(
        arkret_sdk::SpaceId::from_event_id(event.event_id()).token_bytes(),
        event.event_id().token_bytes()
    );
    assert_eq!(op.payload()["object"]["schema"], "ak.schema.space.v1");
    // The create payload carries no object id (spec `common-fields.md` §6.0).
    assert!(op.payload()["object"].get("id").is_none());
    assert_eq!(
        op.payload()["object"]["realm_id"],
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert!(op.payload()["object"].get("space_id").is_none());
    assert_eq!(op.payload()["object"]["kind"], "list");
    assert_eq!(
        op.payload()["object"]["parent_space_id"],
        "ak:space:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2"
    );
    assert_eq!(op.payload()["object"]["rank"], "U");
    assert_eq!(
        op.payload()["object"]["created_by"],
        json!({"kind": "account", "account_id": {
            "principal_id": "ak:did_core:web:alice",
            "station_id": "ak:did_core:web:principal.example"
        }})
    );
    let created_at = op.payload()["object"]["created_at"].as_str().unwrap();
    arkret_sdk::canonical::validate_timestamp_canonical(created_at).unwrap();
    let authored = authored(&op);
    let event_wire = serde_json::to_value(authored.event()).unwrap();
    arkret_sdk::canonical::validate_timestamp_canonical(event_wire["created_at"].as_str().unwrap())
        .unwrap();
}

#[test]
fn canonical_digest_is_stable_across_key_order() {
    let op_a = message_builder(
        "ak:realm:Ac3EwB_awdKZ0dXZDsjIRnTX_zdhqT84eUG5NXqUbg0f",
        "did:web:alice",
        "hello",
    )
    .build("node");
    let event_a = authored(&op_a);

    // Same members, different source order.
    let event_b = author_intent_for_test(
        serde_json::from_value::<EventIntent>(
            serde_json::to_value(&{
                let mut reordered = serde_json::to_value(op_a.intent()).unwrap();
                reordered.as_object_mut().unwrap().insert(
                    "payload".to_owned(),
                    serde_json::from_value(json!({
                        "content": {
                            "body": "hello",
                            "format": "plain",
                            "kind": "ak.content.text"
                        },
                        "strand_id": "ak:strand:AXA352XtBodUhnMN_nDxOloEHVn0_yAotxiYxbyU38Df",
                        "track_name": "discussion"
                    }))
                    .unwrap(),
                );
                reordered
            })
            .unwrap(),
        )
        .unwrap(),
    );

    assert_eq!(event_a.event_id(), event_b.event_id());
    assert_eq!(
        event_a
            .canonical_digest(arkret_sdk::DigestSuite::Sha256)
            .unwrap(),
        event_b
            .canonical_digest(arkret_sdk::DigestSuite::Sha256)
            .unwrap()
    );
}

#[test]
fn sign_ed25519_attaches_typed_proof() {
    use ed25519_dalek::SigningKey;
    let op = message_builder(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "did:web:alice",
        "hi",
    )
    .build("node");
    // Only an authored envelope can be signed: a proof binds an identity, so
    // there is nothing to sign until one exists.
    let mut event = authored(&op);
    let identity = event.event_id().clone();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    event
        .sign_ed25519("did:web:alice", "did:web:alice#k1", &signing_key)
        .expect("sign ok");
    let proof = event.producer_proof.as_ref().expect("proof present");
    assert_eq!(proof.verification_method, "did:web:alice#k1");
    assert!(proof.event_digest.as_str().starts_with("sha256:"));
    // JWS layout: header.. (detached) ..sig — 3 parts separated by '.'.
    assert_eq!(proof.jws.matches('.').count(), 2);
    assert!(event.require_proof().is_ok());
    // Attaching the proof does not move the identity it committed to.
    assert_eq!(event.event_id(), &identity);
    event.verify_identity().unwrap();
}

#[test]
fn authoring_a_built_write_yields_an_unsigned_envelope_ready_to_sign() {
    let op = message_builder(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "did:web:alice.example",
        "hi",
    )
    .build("node");

    let event = authored(&op);

    assert!(event.producer_proof.is_none());
    assert_eq!(event.kind.as_str(), "ak.message.create");
    assert_eq!(
        Some(&event.realm_id),
        op.realm_id_opt(),
        "the authored envelope stays in the write's Realm"
    );
}

#[test]
fn a_signed_envelope_keeps_the_digest_its_proof_committed_to() {
    use ed25519_dalek::SigningKey;

    let op = message_builder(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "did:web:alice.example",
        "hi",
    )
    .build("node");
    let mut event = authored(&op);
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    event
        .sign_ed25519(
            "did:web:alice.example",
            "did:web:alice.example#k1",
            &signing_key,
        )
        .expect("sign ok");

    let local_digest = event
        .canonical_digest(arkret_sdk::DigestSuite::Sha256)
        .unwrap();
    assert_eq!(
        event
            .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap()
            .as_str(),
        local_digest
    );
    assert_eq!(
        event.require_proof().unwrap().event_digest.as_str(),
        local_digest
    );
}

#[test]
fn require_proof_fails_when_unsigned() {
    let op = message_builder(
        "ak:realm:Ac3EwB_awdKZ0dXZDsjIRnTX_zdhqT84eUG5NXqUbg0f",
        "did:web:alice",
        "hi",
    )
    .build("node");
    let mut event = authored(&op);
    event.clear_producer_proof();
    assert!(event.require_proof().is_err());
}

#[test]
fn invite_helpers_emit_canonical_kinds() {
    let invite_id = "ak:invite:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
    let introduction_evidence_digest =
        crate::canonical::canonical_sha256(&json!({"kind": "explicit_address"})).unwrap();
    let invitee_account_id = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:server.example").unwrap(),
    );
    let create = ak_ops::invite_create_structured(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "did:web:alice.example",
        invitee_account_id.clone(),
        Some("member"),
        &introduction_evidence_digest,
    )
    .expect("builds")
    .build("node");
    assert_eq!(create.kind().as_str(), "ak.invite.create");
    assert!(!create.payload().contains_key("invite_id"));
    assert_eq!(
        create.payload()["invitee_account_id"],
        json!({
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:server.example"
        })
    );
    assert_eq!(
        create.payload()["introduction_evidence_digest"],
        introduction_evidence_digest
    );
    assert!(
        arkret_sdk::canonical::validate_timestamp_canonical(
            create.payload()["expires_at"].as_str().unwrap()
        )
        .is_ok()
    );
    assert_eq!(create.payload()["x_role"], "member");
    assert!(
        create
            .payload()
            .get("expires_at")
            .and_then(|value| value.as_str())
            .is_some()
    );
    assert!(!create.payload().contains_key("target"));
    assert!(!create.payload().contains_key("role"));
    assert!(!create.payload().contains_key("state"));
    assert_registered_payload_valid(&create);

    // Third-party form: the Invite stores no account, so the payload carries
    // none.
    let accept = ak_ops::invite_accept(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "did:web:bob.example",
        invite_id,
        None,
        arkret_sdk::InvitePreviousState::Claimed,
    )
    .expect("builds")
    .build("node");
    assert_eq!(accept.kind().as_str(), "ak.invite.accept");
    assert_eq!(accept.payload()["invite_id"], invite_id);
    assert_eq!(accept.payload()["previous_state"], "claimed");
    assert!(!accept.payload().contains_key("state"));
    assert!(!accept.payload().contains_key("invitee_account_id"));
    assert_registered_payload_valid(&accept);

    // Directed form carries the complete invitee account in the signed payload.
    let directed_accept = ak_ops::invite_accept(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "did:web:bob.example",
        invite_id,
        Some(invitee_account_id.clone()),
        arkret_sdk::InvitePreviousState::Pending,
    )
    .expect("builds")
    .build("node");
    assert_eq!(directed_accept.payload()["invite_id"], invite_id);
    assert_eq!(directed_accept.payload()["previous_state"], "pending");
    assert_eq!(
        directed_accept.payload()["invitee_account_id"],
        json!({
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:server.example"
        })
    );
    assert_registered_payload_valid(&directed_accept);

    let bob = crate::test_support::authority("ak:did_core:web:bob.example");
    let cancel = ak_ops::invite_cancel(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "did:web:alice.example",
        invite_id,
        &bob,
        "revoked",
        Some("expired"),
    )
    .expect("builds")
    .build("node");
    assert_eq!(cancel.kind().as_str(), "ak.invite.cancel");
    assert_eq!(cancel.payload()["invite_id"], invite_id);
    assert_eq!(cancel.payload()["reason"], "expired");
    assert_eq!(
        cancel.payload()["invitee_account_id"],
        json!({
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:principal.example"
        })
    );
    // `target_state` is the signed requested lifecycle transition; the retired
    // `state` alias must not be emitted alongside it.
    assert_eq!(cancel.payload()["target_state"], "revoked");
    assert_eq!(cancel.payload()["previous_state"], "pending");
    assert!(!cancel.payload().contains_key("state"));
    assert_registered_payload_valid(&cancel);
    // `event-envelope.schema.json` restricts the enum to rejected / revoked on
    // this kind, so the builder refuses anything else rather than shipping an
    // Event that would be rejected at admission.
    assert!(
        ak_ops::invite_cancel(
            "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            "did:web:alice.example",
            invite_id,
            &bob,
            "expired",
            None,
        )
        .is_err()
    );

    let revoke = ak_ops::invite_revoke(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "did:web:alice.example",
        invite_id,
        None,
        arkret_sdk::InviteRevokePreviousState::Pending,
        "revoked",
        "admin_revoke",
    )
    .expect("token invite revoke builds")
    .build("node");
    assert_eq!(revoke.kind().as_str(), "ak.invite.revoke");
    assert_eq!(revoke.payload()["target_state"], "revoked");
    assert_eq!(revoke.payload()["previous_state"], "pending");
    assert_eq!(revoke.payload()["reason"], "admin_revoke");
    assert!(!revoke.payload().contains_key("invitee_account_id"));
}

#[test]
fn space_lifecycle_helpers_emit_canonical_kinds() {
    let container_space_id = "ak:space:Af5YDKFhOiySm76T_pF7GQrzaF8vEejTcqTWpmnqGUid";
    let archive = ak_ops::realm_archive(
        "ak:realm:AZ7DNT9vCENKLtcPIF0C8XeSO8NfAhWfKokXMXi127n4",
        "did:web:alice.example",
        container_space_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(archive.kind().as_str(), "ak.space.archive");
    assert_eq!(archive.payload()["space_id"], container_space_id);
    assert_eq!(archive.local_target_ref(), Some(container_space_id));

    let restore = ak_ops::space_restore(
        "ak:realm:AZ7DNT9vCENKLtcPIF0C8XeSO8NfAhWfKokXMXi127n4",
        "did:web:alice.example",
        container_space_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(restore.kind().as_str(), "ak.space.restore");
    assert_eq!(restore.payload()["space_id"], container_space_id);
    assert_eq!(restore.local_target_ref(), Some(container_space_id));
}

#[test]
fn strand_lifecycle_helpers_emit_canonical_kinds() {
    let strand_id = "ak:strand:ARkwFWDTPrObvpqVAL9kBsWkK8GrMr5FDO--3PcMFEwU";
    let archive = ak_ops::strand_archive(
        "ak:realm:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
        "did:web:alice.example",
        strand_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(archive.kind().as_str(), "ak.strand.archive");
    assert_eq!(archive.payload()["target_ref"], strand_id);
    assert!(!archive.payload().contains_key("strand_id"));
    assert_eq!(archive.local_target_ref(), Some(strand_id));
    assert_registered_payload_valid(&archive);

    let restore = ak_ops::strand_restore(
        "ak:realm:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
        "did:web:alice.example",
        strand_id,
    )
    .expect("builds")
    .build("node");
    assert_eq!(restore.kind().as_str(), "ak.strand.restore");
    assert_eq!(restore.payload()["target_ref"], strand_id);
    assert!(!restore.payload().contains_key("strand_id"));
    assert_eq!(restore.local_target_ref(), Some(strand_id));
    assert_registered_payload_valid(&restore);
}

#[test]
fn message_revise_builder_uses_content_payload_schema() {
    let message_id = "ak:message:AfXCJ1DUe3g7MVHuVBpMsl89749WyrXAJP7EvoU9mwBH";
    let event = ak_ops::message_revise_content(
        "ak:realm:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8",
        "did:web:alice.example",
        message_id,
        arkret_sdk::ContentBlock::text("updated body"),
    )
    .expect("builds")
    .build("node");

    assert_eq!(event.kind().as_str(), "ak.message.revise");
    assert_eq!(event.payload()["message_id"], message_id);
    assert_eq!(event.payload()["content"]["kind"], "ak.content.text");
    assert_eq!(event.payload()["content"]["body"], "updated body");
    assert!(!event.payload().contains_key("patch"));
    assert_registered_payload_valid(&event);
}

// ── ak.realm.organization builder snapshot + negative tests ──
//
// Covers the builder: active / revoked payload snapshots against
// the registered spec schema, plus negative coverage for missing delegation,
// missing proof, and the status / revocation coupling. These are the
// client-side counterparts of the SDK statement verifier tests; the helper
// produces real `ak.realm.organization` events that cotest can reuse.
mod realm_organization_builder_tests {
    use arkret_models_collaboration::events_payloads::{
        RealmOrganizationAuthorization, RealmOrganizationControlScope, RealmOrganizationIssuerRole,
        RealmOrganizationRelationship, RealmOrganizationStatus, SignatureMaterial,
    };
    use chrono::TimeZone;

    use super::*;

    const REALM_ID: &str = "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";
    const ACTOR: &str = "did:web:alice.example";
    const ORGANIZATION_ID: &str = "ak:did_core:webvh:example.test";
    const ORG_VM: &str = "did:webvh:example.test:orgs:org1#k1";

    fn signed_at() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn organization_id() -> arkret_sdk::DidCoreId {
        arkret_sdk::DidCoreId::new(ORGANIZATION_ID.to_owned()).unwrap()
    }

    fn direct_org_auth() -> RealmOrganizationAuthorization {
        // Organization is a non-delegated role: no delegation_ref.
        RealmOrganizationAuthorization {
            issuer_id: organization_id(),
            issuer_role: RealmOrganizationIssuerRole::Organization,
            verification_method: arkret_sdk::DidUrl::new(ORG_VM).unwrap(),
            delegation_ref: None,
            executed_by: None,
            signed_at: signed_at(),
            proof: SignatureMaterial::NonEmptyString(
                arkret_sdk::NonEmptyString::new("c2ln").unwrap(),
            ),
        }
    }

    fn delegated_org_auth() -> RealmOrganizationAuthorization {
        RealmOrganizationAuthorization {
            issuer_id: crate::mls_api_helpers::principal_core_id("did:web:gov.example").unwrap(),
            issuer_role: RealmOrganizationIssuerRole::GovernanceService,
            verification_method: arkret_sdk::DidUrl::new("did:web:gov.example#k1").unwrap(),
            delegation_ref: Some(
                "ak:grant:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH".to_owned(),
            ),
            executed_by: None,
            signed_at: signed_at(),
            proof: SignatureMaterial::NonEmptyString(
                arkret_sdk::NonEmptyString::new("c2ln").unwrap(),
            ),
        }
    }

    #[test]
    fn active_statement_matches_registered_payload_schema() {
        let event = ak_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-1",
            &organization_id(),
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

        assert_eq!(event.kind().as_str(), "ak.realm.organization");
        // The statement and event target bind the stable organization id.
        assert_eq!(event.local_target_ref(), Some(ORGANIZATION_ID));
        assert_eq!(
            event.payload()["organization_id"],
            "ak:did_core:webvh:example.test"
        );
        assert_eq!(event.payload()["relationship"], "owner");
        assert_eq!(event.payload()["status"], "active");
        assert!(!event.payload().contains_key("revokes_statement_id"));
        // The organization proof is carried verbatim, not synthesized from the
        // local login session.
        assert_eq!(
            event.payload()["authorization"]["issuer_role"],
            "organization"
        );
        assert_eq!(event.payload()["authorization"]["proof"], "c2ln");
        assert_payload_field_names_are_spec_canonical(event.payload());
        assert_registered_payload_valid(&event);
    }

    #[test]
    fn delegated_active_statement_carries_delegation_ref() {
        let event = ak_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-gov",
            &organization_id(),
            RealmOrganizationRelationship::Governance,
            RealmOrganizationStatus::Active,
            vec![RealmOrganizationControlScope::ModerationPolicy],
            signed_at(),
            delegated_org_auth(),
            None,
        )
        .expect("builds")
        .build("node");

        assert_eq!(event.payload()["relationship"], "governance");
        assert_eq!(
            event.payload()["authorization"]["issuer_role"],
            "governance_service"
        );
        assert_eq!(
            event.payload()["authorization"]["delegation_ref"],
            "ak:grant:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH"
        );
        assert_registered_payload_valid(&event);
    }

    #[test]
    fn revoked_statement_matches_registered_payload_schema() {
        let event = ak_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-2",
            &organization_id(),
            RealmOrganizationRelationship::Owner,
            RealmOrganizationStatus::Revoked,
            vec![RealmOrganizationControlScope::OfficialBadge],
            signed_at(),
            direct_org_auth(),
            Some("org-stmt-1".to_owned()),
        )
        .expect("builds")
        .build("node");

        assert_eq!(event.payload()["status"], "revoked");
        assert_eq!(event.payload()["revokes_statement_id"], "org-stmt-1");
        assert_registered_payload_valid(&event);
    }

    #[test]
    fn revoked_without_revokes_statement_id_is_rejected() {
        let error = ak_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-3",
            &organization_id(),
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
        let error = ak_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-4",
            &organization_id(),
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
        let error = ak_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-5",
            &organization_id(),
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
        auth.delegation_ref =
            Some("ak:grant:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH".to_owned());
        let error = ak_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-6",
            &organization_id(),
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
        assert!(
            arkret_sdk::NonEmptyString::new(String::new()).is_err(),
            "the strong type boundary must reject an empty proof"
        );
    }

    #[test]
    fn empty_control_scopes_is_rejected() {
        let error = ak_ops::realm_organization_statement(
            REALM_ID,
            ACTOR,
            "org-stmt-8",
            &organization_id(),
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
