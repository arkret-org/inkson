use super::super::*;
use crate::ephemeral::{
    build_presence_envelope, build_receipt_read_envelope, build_typing_envelope,
    validate_outgoing_registered_event_payload,
};
use crate::event_builders::{
    build_device_message_envelope, build_member_state_invite_accept_event,
    build_member_state_transition_event, build_realm_bootstrap_events, build_realm_create_event,
    build_signed_device_verification_proof, build_space_create_event,
    ensure_device_verification_proof_is_signed, recommended_history_sharing_policy_for_visibility,
};
use crate::operation::OperationBuilder;
use crate::projection_views::{
    LifecycleProjectionView, SpaceContainerProjectionView, StrandProjectionView,
};
use crate::realm_defaults::RECOMMENDED_REALM_ENCRYPTION_FLOOR;
use crate::realm_helpers::{
    canonical_space_join_rule_v1, patch_touches_create_locked_encryption_profile,
};

#[test]
fn realm_metadata_patch_rejects_create_locked_encryption_profile() {
    assert!(patch_touches_create_locked_encryption_profile(&json!({
        "encryption_profile": "none"
    })));
    assert!(patch_touches_create_locked_encryption_profile(&json!({
        "/encryption_profile": { "$op": "replace", "value": "none" }
    })));
    assert!(patch_touches_create_locked_encryption_profile(&json!({
        "object": {
            "value": {
                "encryption_profile": "none"
            }
        }
    })));
    assert!(!patch_touches_create_locked_encryption_profile(&json!({
        "title": "Renamed Realm",
        "summary": "Still editable"
    })));
}

#[test]
fn lifecycle_projection_response_accepts_spec_keys() {
    let canonical_spaces: LifecycleProjectionView<SpaceContainerProjectionView> =
        serde_json::from_value(json!({
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "total": 1,
            "spaces": [{
                "space_id": "ck:space:01904100-0000-7000-8000-f10dc0000001",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "kind": "board",
                "title": "Launch board",
                "state": "active"
            }]
        }))
        .unwrap();
    assert_eq!(
        canonical_spaces.items[0].space_id,
        "ck:space:01904100-0000-7000-8000-f10dc0000001"
    );

    let strands: LifecycleProjectionView<StrandProjectionView> = serde_json::from_value(json!({
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "strands": [{
            "strand_id": "ck:strand:01904100-0000-7000-8000-f20dc0000001",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "title": "Card",
            "summary": "Projection-backed card",
            "board_space_id": "ck:space:01904100-0000-7000-8000-b0ard0000001",
            "list_space_id": "ck:space:01904100-0000-7000-8000-l15t00000001",
            "rank": "U",
            "fields": { "labels": ["demo"] },
            "state": "archived"
        }]
    }))
    .unwrap();
    assert_eq!(strands.items[0].realm_id, strands.realm_id);
    assert_eq!(strands.items[0].state, "archived");
    assert_eq!(
        strands.items[0].board_space_id.as_deref(),
        Some("ck:space:01904100-0000-7000-8000-b0ard0000001")
    );
}

#[test]
fn typing_envelope_uses_spec_ephemeral_shape() {
    let envelope = build_typing_envelope(
        "ck:realm:0196419b-0000-7000-8000-000000000000",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "ck:strand:01964200-0000-7000-8000-000000000001",
        true,
    )
    .unwrap();

    assert_eq!(envelope.kind, "ck.typing");
    assert_eq!(
        envelope.realm_id.to_string(),
        "ck:realm:0196419b-0000-7000-8000-000000000000"
    );
    assert_eq!(
        envelope.payload["strand_id"],
        "ck:strand:01964200-0000-7000-8000-000000000001"
    );
    assert!(envelope.payload.get("scope_id").is_none());
    assert_eq!(
        envelope.payload["realm_id"],
        "ck:realm:0196419b-0000-7000-8000-000000000000"
    );
    assert_eq!(envelope.payload["actor_id"], "did:web:alice.example");
    assert_eq!(envelope.payload["track_name"], "discussion");
    assert_eq!(envelope.payload["typing"], true);
    assert!(
        !serde_json::to_value(&envelope)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("schema")
    );
}

#[test]
fn read_receipt_envelope_uses_actor_not_event_as_sender() {
    let envelope = build_receipt_read_envelope(
        "ck:realm:0196419b-0000-7000-8000-000000000000",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "ck:strand:01964200-0000-7000-8000-000000000001",
        "ck:event:01904100-0000-7000-8000-4a4116cba4e8",
    )
    .unwrap();

    assert_eq!(envelope.kind, "ck.receipt.read");
    assert_eq!(envelope.actor_id.to_string(), "did:web:alice.example");
    assert_eq!(
        envelope.realm_id.to_string(),
        "ck:realm:0196419b-0000-7000-8000-000000000000"
    );
    assert_eq!(envelope.payload["actor_id"], "did:web:alice.example");
    assert_eq!(
        envelope.payload["read_scope"],
        json!({
            "kind": "strand",
            "ref": "ck:strand:01964200-0000-7000-8000-000000000001",
            "track_name": "discussion"
        })
    );
    assert_eq!(
        envelope.payload["event_id"],
        "ck:event:01904100-0000-7000-8000-4a4116cba4e8"
    );
    assert_eq!(envelope.payload["schema"], "ck.schema.read_receipt.v1");
    assert!(
        !serde_json::to_value(&envelope)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("schema")
    );
}

#[test]
fn presence_envelope_buckets_last_active_at_to_hour() {
    let last_active_at = chrono::DateTime::parse_from_rfc3339("2026-06-22T10:34:56.789Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let envelope = build_presence_envelope(
        "ck:realm:0196419b-0000-7000-8000-000000000000",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "online",
        Some("On vacation until May 5"),
        Some(last_active_at),
    )
    .unwrap();

    assert_eq!(envelope.kind, "ck.presence");
    assert_eq!(
        envelope.payload["realm_id"],
        "ck:realm:0196419b-0000-7000-8000-000000000000"
    );
    assert_eq!(envelope.payload["actor_id"], "did:web:alice.example");
    assert_eq!(envelope.payload["state"], "online");
    assert_eq!(
        envelope.payload["status_message"],
        "On vacation until May 5"
    );
    assert_eq!(
        envelope.payload["last_active_at"],
        "2026-06-22T10:00:00Z/PT1H"
    );
    assert_eq!(envelope.payload["ttl_ms"], 30000);
}

#[test]
fn presence_envelope_rejects_non_canonical_state_and_bad_status_message() {
    // Matrix-legacy `unavailable` is not a closed-set v1 state.
    assert!(
        build_presence_envelope(
            "ck:realm:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "unavailable",
            None,
            None,
        )
        .is_err()
    );
    // status_message over 256 code points fails closed at build time.
    let long = "字".repeat(257);
    assert!(
        build_presence_envelope(
            "ck:realm:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "dnd",
            Some(long.as_str()),
            None,
        )
        .is_err()
    );
}

#[test]
fn canonical_space_join_rule_keeps_v1_invite_value() {
    assert_eq!(canonical_space_join_rule_v1("open"), "public");
    assert_eq!(canonical_space_join_rule_v1("request"), "knock");
    assert_eq!(canonical_space_join_rule_v1("invite_only"), "invite");
    assert_eq!(canonical_space_join_rule_v1("invite"), "invite");
}

#[test]
fn space_bootstrap_events_use_canonical_create_and_facet_kinds() {
    let events = build_realm_bootstrap_events(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice.example",
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
        &["did:web:bob.example".to_owned()],
        &["did:web:server.example".to_owned()],
        None,
        None,
    )
    .unwrap();
    let kinds = events
        .iter()
        .map(|event| event.kind.as_str())
        .collect::<Vec<_>>();
    // Spec realm-and-space.md §2.6: the creator-join cell is
    // populated atomically by the reducer when it accepts
    // `ck.realm.create`. The bootstrap chain MUST NOT include an
    // explicit `ck.member.state{join}` for the creator.
    assert_eq!(
        kinds,
        vec![
            "ck.realm.create",
            "ck.realm.policy_components",
            "ck.realm.join_rule",
            "ck.realm.history_visibility",
            "ck.realm.history_sharing_policy",
            "ck.realm.discovery",
            "ck.realm.plaintext_visible_services",
            "ck.member.state",
        ]
    );

    let create = &events[0];
    assert_eq!(create.payload["object"]["schema"], "ck.schema.realm.v1");
    // Spec rename (head 37ce729 / SDK 4d5a1af): realm.schema.json
    // `created_by_principal` → `created_by`.
    assert_eq!(
        create.payload["object"]["created_by"],
        create.actor_id.as_str()
    );
    assert_eq!(
        create.payload["object"]["created_at"].as_str().unwrap(),
        create
            .created_at
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "Realm create cross-field semantic validation requires matching timestamps",
    );
    assert_eq!(create.payload["object"]["default_join_rule"], "invite");
    assert_eq!(create.payload["object"]["history_visibility"], "shared");
    assert!(create.payload["object"]["content_encryption_floor"].is_null());
    assert!(create.payload["object"]["metadata_encryption_floor"].is_null());
    assert_eq!(create.payload["object"]["notary"]["type"], "single_did");
    assert_eq!(
        create.payload["object"]["notary"]["did"],
        create.actor_id.as_str()
    );
    assert_eq!(
        create.payload["object"]["notary"]["recovery_members"][0],
        "did:web:alice.example:recovery:notary",
    );
    assert_eq!(
        create.payload["object"]["notary"]["controller_organization"],
        "did:web:alice.example",
    );
    assert_eq!(
        create.payload["object"]["notary"]["recovery_controller_organizations"][0],
        "did:web:alice.example:recovery",
    );
    assert_eq!(
        create.effects[0].cell.to_string(),
        "ck:cell:ck.component.realm.create.v1:ck:realm:0196419b-0000-7000-8000-000000000001"
    );
    assert_eq!(create.effects[0].op.op_type, cokret_sdk::LatticeOpType::Set);
    // seal_ref starts unset on the typed envelope. Realm genesis
    // has no snapshot head yet, so the create event relies on its
    // `head_eq null` precondition instead of a prior seal.
    assert!(create.seal_ref.is_none());
    // The typed builder leaves the envelope unsigned — the active
    // signer attaches the detached JWS proof at submit time.
    assert!(create.proofs.is_empty());

    // Bootstrap order: create, encryption floor policy, join_rule,
    // history_visibility, history_sharing_policy, discovery,
    // plaintext_visible, member-invite.
    assert_eq!(
        events[1].payload["value"]["content_encryption_floor"],
        RECOMMENDED_REALM_ENCRYPTION_FLOOR
    );
    assert_eq!(
        events[1].payload["value"]["metadata_encryption_floor"],
        RECOMMENDED_REALM_ENCRYPTION_FLOOR
    );
    assert_eq!(events[1].payload["value"]["policy_revision"], 1);
    assert_eq!(
        events[1].payload["value"]["content_scheme"],
        "mls-exporter-aead-v1"
    );
    assert_eq!(events[2].payload["value"], "invite");
    assert_eq!(events[3].payload["value"], "shared");
    assert_eq!(
        events[4].payload["value"]["default_key_share"],
        "event_time_visibility"
    );
    assert_eq!(
        events[4].payload["value"]["pre_join_history"],
        "allow_if_visibility_allows"
    );
    assert_eq!(
        events[4].payload["value"]["allowed_key_sources"],
        json!(["verified_member_device"])
    );
    assert_eq!(
        events[4].payload["value"]["allowed_receiver_states"],
        json!(["active_member"])
    );
    assert_eq!(
        events[4].payload["value"]["audit"],
        json!({
            "share_audit_event_required": false,
            "access_audit_required": false
        })
    );
    assert_eq!(events[5].payload["value"], "listed");
    assert_eq!(
        events[6].payload["services"][0]["service_did"],
        "did:web:server.example"
    );
    assert_eq!(
        events[6].payload["services"][0]["data_classes"],
        json!([
            "message_content",
            "full_text_index",
            "notification_summary",
            "inbox_preview",
        ])
    );
    assert_eq!(events[7].payload["membership"], "invite");
}

#[test]
fn plaintext_realm_create_does_not_claim_e2ee_floors() {
    let envelope = build_realm_create_event(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice.example",
        "Public updates",
        None,
        "listed",
        "public",
        "world_readable",
        "none",
        "standard",
        "open",
        "single_did",
        "sha256",
        "ck:trust_domain:server.example",
        &[],
        None,
        None,
    )
    .unwrap();

    assert_eq!(envelope.payload["object"]["encryption_profile"], "none");
    assert!(envelope.payload["object"]["content_encryption_floor"].is_null());
    assert!(envelope.payload["object"]["metadata_encryption_floor"].is_null());
}

#[test]
fn realm_bootstrap_rejects_prejoin_history_with_strict_mls_scheme() {
    let err = build_realm_bootstrap_events(
        "ck:realm:0196419b-0000-7000-8000-000000000011",
        "did:web:alice.example",
        "Strict history",
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
        &[],
        &[],
        None,
        Some("mls-rfc9420"),
    )
    .expect_err("pre-join history requires the history-capable content scheme");

    assert!(
        err.to_string()
            .contains(cokret_sdk::error::REASON_HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME)
    );
}

#[test]
fn realm_bootstrap_allows_joined_history_with_strict_mls_scheme() {
    let events = build_realm_bootstrap_events(
        "ck:realm:0196419b-0000-7000-8000-000000000012",
        "did:web:alice.example",
        "Strict history",
        None,
        "listed",
        "invite",
        "joined",
        "mls_rfc9420",
        "standard",
        "restricted",
        "single_did",
        "sha256",
        "ck:trust_domain:server.example",
        &[],
        &[],
        None,
        Some("mls-rfc9420"),
    )
    .expect("joined history is valid with the strict MLS content scheme");

    assert_eq!(events[1].payload["value"]["content_scheme"], "mls-rfc9420");
}

#[test]
fn default_history_sharing_policy_matches_prejoin_visibility() {
    let shared = recommended_history_sharing_policy_for_visibility("shared")
        .expect("shared visibility should install a key sharing policy");
    assert_eq!(shared["default_key_share"], "event_time_visibility");
    assert_eq!(shared["pre_join_history"], "allow_if_visibility_allows");
    assert_eq!(
        shared["allowed_key_sources"],
        json!(["verified_member_device"])
    );
    assert_eq!(shared["allowed_receiver_states"], json!(["active_member"]));
    assert_eq!(
        shared["audit"],
        json!({
            "share_audit_event_required": false,
            "access_audit_required": false
        })
    );
    assert!(recommended_history_sharing_policy_for_visibility("joined").is_none());
}

/// Regression: every genesis bootstrap envelope must produce the SAME
/// canonical digest whether hashed by yougen's local builder or after a
/// round-trip through the authoritative `cokret_sdk::Event` wire model.
///
/// The bug this guards: genesis preconditions assert `head_eq null` (an
/// empty cell) and member transitions move `from: null → join`, both of
/// which carry an EXPLICIT wire `null`. An earlier `Option<Value>` field on
/// the SDK `Predicate` / `LatticeOp` collapsed that `null` to `None` on
/// deserialize and dropped it on re-serialize, so the SDK digest no longer
/// matched the locally-signed one — the SDK submit path failed closed
/// with "event digest drift between yougen builder and SDK Event" and the
/// Realm could never be created.
#[test]
fn bootstrap_envelopes_have_no_sdk_digest_drift() {
    let events = build_realm_bootstrap_events(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice.example",
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
        // an invitee exercises the `ck.member.state` `from: null → invite`
        // transition (LatticeOp.from carries an explicit null). Bootstrap
        // accepts only authoritative DID input; handle strings require
        // Directory-resolved invite/address evidence.
        &["did:webvh:z2dmjBobScidVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:bob.example".to_owned()],
        &["did:web:server.example".to_owned()],
        None,
        None,
    )
    .unwrap();

    for event in events {
        let kind = event.kind.as_str().to_owned();
        let digest = event
            .event_digest()
            .unwrap_or_else(|err| panic!("{kind}: SDK event_digest: {err}"));
        let roundtrip: cokret_sdk::Event = serde_json::from_value(
            serde_json::to_value(&event).unwrap_or_else(|err| panic!("{kind}: to_value: {err}")),
        )
        .unwrap_or_else(|err| panic!("{kind}: SDK roundtrip: {err}"));
        let roundtrip_digest = roundtrip
            .event_digest()
            .unwrap_or_else(|err| panic!("{kind}: roundtrip event_digest: {err}"));
        assert_eq!(digest, roundtrip_digest, "{kind}: SDK digest drift");
    }
}

#[test]
fn realm_bootstrap_rejects_handle_seed_without_directory_evidence() {
    let err = build_realm_bootstrap_events(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice.example",
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
        &["bob:example.com".to_owned()],
        &[],
        None,
        None,
    )
    .expect_err("handle seed members require Directory-resolved evidence");
    assert!(
        err.to_string()
            .contains("handle bootstrap requires a Directory-resolved invite address")
    );
}

#[test]
fn member_state_invite_accept_event_carries_invite_ref() {
    let event = build_member_state_invite_accept_event(
        "ck:realm:0196419b-0000-7000-8000-000000000010",
        "did:web:bob.example",
        "ck:invite:0196419b-0000-7000-8000-000000000020",
    )
    .expect("invite accept event");

    assert_eq!(event.kind.as_str(), "ck.member.state");
    assert_eq!(
        event.realm_id.as_str(),
        "ck:realm:0196419b-0000-7000-8000-000000000010"
    );
    assert_eq!(event.actor_id.as_str(), "did:web:bob.example");
    // Spec `membership_payload` requires `realm_id` in the body for join.
    assert_eq!(
        event.payload["realm_id"],
        "ck:realm:0196419b-0000-7000-8000-000000000010"
    );
    assert_eq!(event.payload["actor_id"], "did:web:bob.example");
    assert_eq!(event.payload["membership"], "join");
    assert_eq!(event.payload["reason"], "invite_accept");
    assert_eq!(
        event.payload["invite_ref"],
        "ck:invite:0196419b-0000-7000-8000-000000000020"
    );
    assert!(event.payload.get("invite_id").is_none());
    assert_eq!(event.payload["delivery_status"], "unroutable");
    assert_eq!(event.preconditions.len(), 1);
    assert_eq!(
        event.preconditions[0].cell.as_str(),
        "ck:cell:ck.component.member.state.v1:did:web:bob.example"
    );
    assert_eq!(
        event.preconditions[0].predicate.value,
        Some(json!("invite"))
    );
    assert_eq!(event.effects.len(), 1);
    assert_eq!(
        event.effects[0].cell.as_str(),
        "ck:cell:ck.component.member.state.v1:did:web:bob.example"
    );
    assert_eq!(event.effects[0].op.from, Some(json!("invite")));
    assert_eq!(event.effects[0].op.to, Some(json!("join")));
}

#[test]
fn member_state_ban_event_uses_realm_scoped_member_cell() {
    let event = build_member_state_transition_event(
        "ck:realm:0196419b-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "did:web:bob.example",
        Some("join"),
        "ban",
        "admin_ban",
    )
    .expect("ban event");

    assert_eq!(event.kind.as_str(), "ck.member.state");
    assert_eq!(
        event.payload["realm_id"],
        "ck:realm:0196419b-0000-7000-8000-000000000010"
    );
    assert_eq!(event.payload["actor_id"], "did:web:bob.example");
    assert_eq!(event.payload["membership"], "ban");
    assert_eq!(event.preconditions.len(), 1);
    assert_eq!(
        event.preconditions[0].cell.as_str(),
        "ck:cell:ck.component.member.state.v1:did:web:bob.example"
    );
    assert_eq!(event.preconditions[0].predicate.value, Some(json!("join")));
    assert_eq!(event.effects.len(), 1);
    assert_eq!(
        event.effects[0].cell.as_str(),
        "ck:cell:ck.component.member.state.v1:did:web:bob.example"
    );
    assert_eq!(event.effects[0].op.from, Some(json!("join")));
    assert_eq!(event.effects[0].op.to, Some(json!("ban")));
}

#[test]
fn outgoing_payload_schema_gate_accepts_sdk_object_patch_payload() {
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000002";
    let mut patch = cokret_sdk::Patch::new();
    patch
        .insert_op(
            "fields.document",
            cokret_sdk::PatchOp::set(json!({ "blocks": [] })),
        )
        .unwrap();
    let payload = cokret_sdk::ObjectPatchPayload::for_target(strand_id, patch)
        .unwrap()
        .to_value()
        .unwrap();
    let event = OperationBuilder::new(
        "ck:realm:0196419b-0000-7000-8000-000000000010",
        "did:web:alice.example",
        cokret_sdk::events::kinds::EventKind::StrandUpdate,
    )
    .target_ref(strand_id)
    .body(payload)
    .build("yougen");

    validate_outgoing_registered_event_payload(event.kind.as_str(), &event.payload).unwrap();
}

/// Contract test: ck.space.create payload must satisfy spec
/// space.schema.json — same validator soland runs on the wire.
#[test]
fn space_create_payload_matches_spec_schema() {
    // Spec requires payload.object.realm_id to match the
    // `^ck:realm:UUID7` pattern; the product Space id remains a
    // separate `ck:space:*` object id.
    let event = build_space_create_event(
        "ck:space:0196419b-0000-7000-8000-000000000010",
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice.example",
        "Roadmap",
        Some("Q3 planning"),
        "board",
        None,
        None,
    )
    .unwrap();
    let catalog = cokret_sdk::schema::event_payload_validator_catalog().unwrap();
    if catalog
        .missing_payload_validators_for(std::iter::once(event.kind.as_str()))
        .is_empty()
        && let Err(error) = catalog.validate_payload(event.kind.as_str(), &event.payload)
    {
        panic!(
            "ck.space.create payload violates spec: {error}\npayload: {}",
            serde_json::to_string_pretty(&event.payload).unwrap_or_default()
        );
    }
}

/// Contract test: every event produced by `build_realm_bootstrap_events`
/// MUST satisfy the spec payload-schema rule for its event kind, using
/// the same `cokret_sdk::schema::event_payload_validator_catalog` that
/// soland runs on the wire. Catches schema drift (missing required
/// fields, wrong patterns) at `cargo test` rather than user runtime.
#[test]
fn realm_bootstrap_payloads_match_spec_schema() {
    let events = build_realm_bootstrap_events(
        "ck:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice.example",
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
        &["did:web:bob.example".to_owned()],
        &["did:web:server.example".to_owned()],
        None,
        None,
    )
    .unwrap();

    let catalog = cokret_sdk::schema::event_payload_validator_catalog().unwrap();
    for event in &events {
        if catalog
            .missing_payload_validators_for(std::iter::once(event.kind.as_str()))
            .is_empty()
            && let Err(error) = catalog.validate_payload(event.kind.as_str(), &event.payload)
        {
            panic!(
                "event kind `{}` payload violates spec schema: {error}\n\
                 payload was: {}",
                event.kind.as_str(),
                serde_json::to_string_pretty(&event.payload).unwrap_or_default()
            );
        }
    }
}

/// R3 — `build_device_message_envelope` MUST emit the canonical
/// `ck.schema.device_message.v1` send shape:
/// `{messages: {<actor>: {<device_id>: {kind, expires_at, content}}}}`.
/// This matches the SDK `DeviceMessageTarget` and `device-lifecycle.md`
/// §7, which both make `kind` and `expires_at` required. If the wire
/// shape drifts (mislabelled `type`, missing `expires_at`, etc.) soland
/// has to fall back to defaults. This test pins the bytes so a refactor
/// cannot change them by accident.
#[test]
fn device_message_envelope_matches_schema_v1() {
    let envelope = build_device_message_envelope(
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-0000000000aa",
        "ck.key.verification.request",
        "2026-04-26T00:10:00Z",
        json!({
            "method": "sas",
            "transaction_id": "verify-001"
        }),
    )
    .expect("device message envelope builds");
    let envelope = serde_json::to_value(envelope).expect("device message envelope serializes");
    assert_eq!(
        envelope,
        json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-0000000000aa": {
                        "kind": "ck.key.verification.request",
                        "expires_at": "2026-04-26T00:10:00Z",
                        "content": {
                            "method": "sas",
                            "transaction_id": "verify-001"
                        }
                    }
                }
            }
        }),
        "wire shape must remain `messages → actor → device_id → {{kind, expires_at, content}}`",
    );
}

/// R3 — empty content is still a valid envelope. `ck.key.verification.done`
/// for example carries only a transaction id; the test ensures we don't
/// require a populated content map.
#[test]
fn device_message_envelope_accepts_minimal_content() {
    let envelope = build_device_message_envelope(
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-0000000000bb",
        "ck.key.verification.done",
        "2026-04-26T00:10:00Z",
        json!({"transaction_id": "verify-done-001"}),
    )
    .expect("device message envelope builds");
    let envelope = serde_json::to_value(envelope).expect("device message envelope serializes");
    let inner = &envelope["messages"]["did:web:bob.example"]["ck:device:01904100-0000-7000-8000-0000000000bb"];
    assert_eq!(inner["kind"], "ck.key.verification.done");
    assert_eq!(inner["expires_at"], "2026-04-26T00:10:00Z");
    assert_eq!(inner["content"]["transaction_id"], "verify-done-001");
}

#[test]
fn device_verification_proof_requires_signed_envelope() {
    assert!(ensure_device_verification_proof_is_signed(&json!({})).is_err());
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let proof = build_signed_device_verification_proof(
        "did:web:alice.example",
        "ck:device:alice",
        "ck:device:bob",
        "sas",
        Some([1234, 5678, 9012]),
        Some("alice-x25519"),
        Some("bob-x25519"),
        &signing,
    )
    .unwrap();
    ensure_device_verification_proof_is_signed(&proof).expect("signed proof");
    assert_eq!(
        proof["device_envelope"]["type"].as_str(),
        Some("ck.device.verification.proof.v1")
    );
    assert_eq!(proof["signature"]["alg"].as_str(), Some("EdDSA"));
    assert!(
        proof["signature"]["event_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(proof["signature"].get("payload_digest").is_none());
    assert_eq!(
        proof["signature"]["jws"]
            .as_str()
            .unwrap()
            .split('.')
            .count(),
        3
    );
}
