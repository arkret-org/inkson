use serde_json::json;

use crate::ephemeral::validate_outgoing_registered_event_payload;
use crate::event_builders::{
    build_member_state_transition_event, build_realm_bootstrap_steps_for_station,
    build_realm_create_event, build_realm_state_event_for_station, build_space_create_event,
};
use crate::operation::TypedOperationBuilder;
use crate::realm_helpers::validate_join_rule_v1;

fn test_genesis_salt() -> arkret_sdk::GenesisSalt {
    arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap()
}

// The five plaintext `EphemeralEnvelope` builder tests that lived here
// (`ak.typing` / `ak.receipt.read` / `ak.presence` shape, presence
// `last_active_at` bucketing, presence state + status_message rejection, and
// the ephemeral proof round-trip) tested a wire object v1 deleted. Their
// substance moved to `crate::signal`: those bodies are now AEAD plaintext, and
// the proof round-trip is asserted against the `ak.signal_proof.v1` transcript
// and the AAD binding instead of the deleted ephemeral binding context.

#[test]
fn canonical_space_join_rule_keeps_v1_invite_value() {
    assert!(validate_join_rule_v1("open").is_err());
    assert!(validate_join_rule_v1("request").is_err());
    assert!(validate_join_rule_v1("invite_only").is_err());
    assert_eq!(validate_join_rule_v1("invite").unwrap(), "invite");
}

#[test]
fn space_bootstrap_events_use_canonical_create_and_facet_kinds() {
    let events = crate::event_submit::author_event_unit_for_test(
        build_realm_bootstrap_steps_for_station(
            crate::test_support::core_id(crate::test_support::STATION_ID),
            test_genesis_salt(),
            "did:web:alice.example",
            "did:web:server.example",
            "https://server.example",
            "Engineering",
            Some("Roadmap work"),
            "listed",
            "invite",
            "all_history_for_current_members",
            "standard",
            "restricted",
            "sha256",
            "ak:trust_domain:server.example",
            &["did:web:server.example".to_owned()],
            None,
        )
        .unwrap(),
    )
    .expect("the Realm bootstrap unit authors");
    let kinds = events
        .iter()
        .map(|event| event.kind.as_str())
        .collect::<Vec<_>>();
    // The creator join is the final explicit slot; create only establishes the
    // identity/security root.
    assert_eq!(
        kinds,
        vec![
            "ak.realm.create",
            "ak.realm.profile",
            "ak.realm.policy_bundle",
            "ak.realm.join_rule",
            "ak.realm.history_access",
            "ak.realm.discovery",
            "ak.realm.plaintext_visible_services",
            "ak.member.state",
        ]
    );
    // realm-and-space.md §2.5: v1 has no founding `ak.capability.grant` slot;
    // genesis authority is the authority-root cell the create contract writes.
    assert!(
        events
            .iter()
            .all(|event| event.kind.as_str() != "ak.capability.grant"),
        "ordinary Realm genesis carries no capability grant"
    );

    let create = &events[0];
    assert_eq!(
        create.payload["object"]["schema"],
        "ak.schema.realm_genesis.v1"
    );
    assert_eq!(create.payload["object"]["purpose"], "collaboration");
    assert_eq!(
        create.payload["object"]["genesis_salt"],
        test_genesis_salt().as_str()
    );
    for forbidden in [
        "title",
        "summary",
        "created_by",
        "created_at",
        "default_join_rule",
        "history_access",
        "content_encryption_floor",
        "metadata_encryption_floor",
    ] {
        assert!(create.payload["object"].get(forbidden).is_none());
    }
    assert_eq!(events[1].payload["schema"], "ak.schema.realm_profile.v1");
    assert_eq!(events[1].payload["title"], "Engineering");
    assert_eq!(events[1].payload["summary"], "Roadmap work");
    assert_eq!(
        create.payload["object"]["governance_station_id"],
        crate::test_support::STATION_ID
    );
    // The typed builder leaves the envelope unsigned — the active
    // signer attaches the detached JWS proof at submit time.
    assert!(create.producer_proof.is_none());

    // Bootstrap order: create, profile, policy bundle, join_rule,
    // history_access, discovery, plaintext_visible, creator member join.
    for removed in [
        "content_encryption_floor",
        "metadata_encryption_floor",
        "encryption_profile",
        "content_scheme",
    ] {
        assert!(
            !events[2].payload.contains_key(removed),
            "Realm policy bundle must not restate {removed}"
        );
    }
    assert_eq!(events[2].payload["policy_revision"], 1);
    assert_eq!(events[3].payload["value"], "invite");
    assert_eq!(events[4].payload["from"], serde_json::Value::Null);
    assert_eq!(events[4].payload["to"], "all_history_for_current_members");
    assert_eq!(events[5].payload["value"]["discoverability"], "listed");
    assert_eq!(
        events[6].payload["services"][0]["service_id"],
        "ak:did_core:web:server.example"
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
    assert_eq!(events[7].payload["membership"], "join");
    assert!(events.iter().all(|event| {
        event
            .payload
            .get("membership")
            .and_then(|value| value.as_str())
            != Some("invite")
    }));
}

#[test]
fn realm_create_carries_only_the_closed_genesis_members() {
    let envelope = build_realm_create_event(
        test_genesis_salt(),
        "did:web:alice.example",
        "listed",
        "public",
        "all_history_for_current_members",
        "standard",
        "ak:trust_domain:server.example",
    )
    .unwrap();

    let object = envelope.payload()["object"]
        .as_object()
        .expect("the genesis object is a JSON object")
        .clone();
    // `ak.schema.realm_genesis.v1` is closed: these nine members and nothing
    // else for a Collaboration Realm. Title, alias, discovery policy and the
    // plaintext service surface are their own facet follow-ups in the same
    // bootstrap unit, never members of the create.
    let mut members = object.keys().cloned().collect::<Vec<_>>();
    members.sort();
    assert_eq!(
        members,
        vec![
            "genesis_salt".to_owned(),
            "governance_station_id".to_owned(),
            "initial_discoverability".to_owned(),
            "initial_history_access".to_owned(),
            "initial_join_rule".to_owned(),
            "purpose".to_owned(),
            "schema".to_owned(),
            "security_class".to_owned(),
            "trust_domain".to_owned(),
        ]
    );
    // Encryption is not a creation-time claim: a scope becomes encrypted only
    // through its own committed `ak.mls.genesis`, so no floor or profile can
    // be asserted here.
    for removed in [
        "encryption_profile",
        "content_encryption_floor",
        "metadata_encryption_floor",
        "created_at",
    ] {
        assert!(
            object.get(removed).is_none(),
            "the genesis object must not carry {removed}"
        );
    }
}

#[test]
fn realm_bootstrap_prejoin_history_does_not_author_retired_encryption_axes() {
    let events = crate::event_submit::author_event_unit_for_test(
        build_realm_bootstrap_steps_for_station(
            crate::test_support::core_id(crate::test_support::STATION_ID),
            test_genesis_salt(),
            "did:web:alice.example",
            "did:web:server.example",
            "https://server.example",
            "Current history policy",
            None,
            "listed",
            "invite",
            "all_history_for_current_members",
            "standard",
            "restricted",
            "sha256",
            "ak:trust_domain:server.example",
            &[],
            None,
        )
        .expect("pre-MLS history policy is authorable without encryption axes"),
    )
    .expect("the Realm bootstrap unit authors");

    // `history_access` is a distinct current policy; no retired create-time
    // encryption axis may leak into any Realm bootstrap Event.
    for retired in [
        "content_scheme",
        "encryption_profile",
        "encryption_floor",
        "e2ee_required",
    ] {
        assert!(
            events
                .iter()
                .all(|event| !event.payload.contains_key(retired)),
            "Realm bootstrap must not author {retired}"
        );
    }
}

/// Regression: every genesis bootstrap envelope must produce the SAME
/// canonical digest whether hashed by inkson's local builder or after a
/// round-trip through the authoritative `arkret_sdk::Event` wire model.
///
/// The bug this guards: genesis preconditions assert `head_eq null` for an
/// absent materialized cell. An earlier `Option<Value>` field on the SDK
/// `Predicate` collapsed that explicit `null` to `None` on deserialize and
/// dropped it on re-serialize, so the SDK digest no longer matched the
/// locally-signed one.
#[test]
fn bootstrap_envelopes_have_no_sdk_digest_drift() {
    let events = crate::event_submit::author_event_unit_for_test(
        build_realm_bootstrap_steps_for_station(
            crate::test_support::core_id(crate::test_support::STATION_ID),
            test_genesis_salt(),
            "did:web:alice.example",
            "did:web:server.example",
            "https://server.example",
            "Engineering",
            None,
            "listed",
            "invite",
            "all_history_for_current_members",
            "standard",
            "restricted",
            "sha256",
            "ak:trust_domain:server.example",
            &["did:web:server.example".to_owned()],
            None,
        )
        .unwrap(),
    )
    .expect("the Realm bootstrap unit authors");

    assert!(
        events
            .iter()
            .all(|event| event.kind.as_str() != "ak.invite.create"
                && !(event.kind.as_str() == "ak.member.state"
                    && event.payload["membership"] == "invite")),
        "Realm genesis must not contain seed invite membership transitions"
    );

    for event in events {
        let kind = event.kind.as_str().to_owned();
        let digest = event
            .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap_or_else(|err| panic!("{kind}: SDK event_digest: {err}"));
        let roundtrip: arkret_sdk::Event = serde_json::from_value(
            serde_json::to_value(event.event())
                .unwrap_or_else(|err| panic!("{kind}: to_value: {err}")),
        )
        .unwrap_or_else(|err| panic!("{kind}: SDK roundtrip: {err}"));
        let roundtrip_digest = roundtrip
            .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap_or_else(|err| panic!("{kind}: roundtrip event_digest: {err}"));
        assert_eq!(digest, roundtrip_digest, "{kind}: SDK digest drift");
    }
}

#[test]
fn member_state_ban_event_uses_realm_scoped_member_payload() {
    let event = build_member_state_transition_event(
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        "did:web:alice.example",
        &crate::mls_api_helpers::local_account_actor_id("did:web:bob.example").unwrap(),
        Some("join"),
        "ban",
        "admin_ban",
    )
    .expect("ban event");

    assert_eq!(event.kind().as_str(), "ak.member.state");
    assert_eq!(
        event.payload()["realm_id"],
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo"
    );
    let member_id: arkret_sdk::ActorId =
        serde_json::from_value(event.payload()["member_id"].clone()).unwrap();
    assert_eq!(
        member_id.signing_principal_id().as_str(),
        "ak:did_core:web:bob.example"
    );
    assert_eq!(event.payload()["membership"], "ban");
}

#[test]
fn outgoing_payload_schema_gate_accepts_sdk_object_patch_payload() {
    let strand_id = "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let mut patch = arkret_sdk::Patch::new();
    patch
        .insert_op(
            "fields.document",
            arkret_sdk::PatchOp::set(json!({ "blocks": [] })),
        )
        .unwrap();
    let payload = arkret_sdk::StrandPatchPayload::for_strand(
        arkret_sdk::StrandId::new(strand_id).unwrap(),
        patch,
    )
    .unwrap();
    let event = TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandUpdate>(
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        "did:web:alice.example",
        payload,
    )
    .target_ref(strand_id)
    .build("inkson");

    validate_outgoing_registered_event_payload(event.kind().as_str(), &event.payload()).unwrap();
}

/// Contract test: ak.space.create payload must satisfy spec
/// space.schema.json — same validator coland runs on the wire.
#[test]
fn space_create_payload_matches_spec_schema() {
    // Spec requires payload.object.realm_id to match the
    // full event-derived `ak:realm:<event-token>` pattern; the Space's own id is absent from a
    // create payload and derived from this Event.
    let event = build_space_create_event(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice.example",
        "Roadmap",
        Some("Q3 planning"),
        "board",
        None,
    )
    .unwrap();
    // `object.created_at` is the same producer-signed timestamp the envelope
    // carries, so they have to agree before the identity is derived from both.
    assert_eq!(
        event.payload()["object"]["created_at"],
        json!(arkret_sdk::canonical::format_timestamp_canonical(
            event.created_at()
        ))
    );
    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    if catalog
        .missing_payload_validators_for(std::iter::once(event.kind().as_str()))
        .is_empty()
        && let Err(error) = catalog.validate_payload(
            event.kind().as_str(),
            &serde_json::to_value(event.payload()).expect("event payload serializes"),
        )
    {
        panic!(
            "ak.space.create payload violates spec: {error}\npayload: {}",
            serde_json::to_string_pretty(&event.payload()).unwrap_or_default()
        );
    }
}

/// Contract test: every event produced by `build_realm_bootstrap_events`
/// MUST satisfy the spec payload-schema rule for its event kind, using
/// the same `arkret_schema_conformance::event_payload_validator_catalog` that
/// coland runs on the wire. Catches schema drift (missing required
/// fields, wrong patterns) at `cargo test` rather than user runtime.
#[test]
fn realm_bootstrap_payloads_match_spec_schema() {
    let _signer_guard =
        crate::event_signer::ActiveSignerTestGuard::replace(Some(std::sync::Arc::new(
            crate::event_signer::build_ed25519_signer([42_u8; 32], "did:web:alice.example"),
        )));
    let events = crate::event_submit::author_event_unit_for_test(
        build_realm_bootstrap_steps_for_station(
            crate::test_support::core_id(crate::test_support::STATION_ID),
            test_genesis_salt(),
            "did:web:alice.example",
            "did:web:server.example",
            "https://server.example",
            "Engineering",
            Some("Roadmap work"),
            "listed",
            "invite",
            "all_history_for_current_members",
            "standard",
            "restricted",
            "sha256",
            "ak:trust_domain:server.example",
            &["did:web:server.example".to_owned()],
            None,
        )
        .unwrap(),
    )
    .expect("the Realm bootstrap unit authors");

    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    for event in &events {
        crate::event_submit::validate_capability_grant_payload(
            &crate::operation::EventIntent::from_authored(event),
        )
        .expect("the inner capability artifact validates before the envelope is signed");
        if catalog
            .missing_payload_validators_for(std::iter::once(event.kind.as_str()))
            .is_empty()
            && let Err(error) = catalog.validate_payload(
                event.kind.as_str(),
                &serde_json::to_value(&event.payload).expect("event payload serializes"),
            )
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

#[test]
fn realm_join_and_discovery_authoring_rejects_values_outside_spec_enums() {
    let _signer_guard =
        crate::event_signer::ActiveSignerTestGuard::replace(Some(std::sync::Arc::new(
            crate::event_signer::build_ed25519_signer([43_u8; 32], "did:web:alice.example"),
        )));
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let actor_id = "ak:did_core:web:alice.example";

    assert!(
        serde_json::from_value::<arkret_sdk::RealmJoinRuleValue>(json!("members_only")).is_err()
    );
    assert!(
        serde_json::from_value::<arkret_sdk::RealmDiscoveryValue>(json!("discoverable")).is_err()
    );
    build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmJoinRule>(
        crate::test_support::core_id(crate::test_support::STATION_ID),
        realm_id,
        actor_id,
        arkret_sdk::DigestSuite::Sha256,
        arkret_sdk::RealmJoinRulePayload::new(arkret_sdk::RealmJoinRuleValue::KnockRestricted),
    )
    .unwrap();
    build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmDiscovery>(
        crate::test_support::core_id(crate::test_support::STATION_ID),
        realm_id,
        actor_id,
        arkret_sdk::DigestSuite::Sha256,
        arkret_sdk::RealmDiscoveryPayload::new(arkret_sdk::RealmDiscoverability::InviteOnly),
    )
    .unwrap();
}
