//! Sender labels and participant-roster identity fields.

use super::*;

#[test]
fn rejects_did_fallback_when_comparing_message_senders() {
    assert!(!is_own_message_sender(
        "did:web:alice.example",
        "ak:did_core:web:alice.example"
    ));
    assert!(!is_own_message_sender(
        "ak:did_core:web:alice.example",
        "did:web:alice.example"
    ));
    assert!(!is_own_message_sender(
        "ak:did_core:web:bob.example",
        "ak:did_core:web:alice.example"
    ));
    assert!(!is_own_message_sender("", "ak:did_core:web:alice.example"));
}

#[test]
fn treats_canonical_principal_id_as_own_sender() {
    let participants = Vec::new();

    assert!(is_own_message_sender(
        "ak:did_core:web:alice.example",
        "ak:did_core:web:alice.example"
    ));
    assert_eq!(
        sender_display_label(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:alice.example",
            "",
            &participants
        ),
        crate::views::helpers::short_protocol_id("ak:did_core:web:alice.example")
    );
    assert_eq!(
        sender_display_label(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:alice.example",
            "Alice Local",
            &participants,
        ),
        "Alice Local"
    );
    assert_eq!(
        sender_display_label(
            "ak:did_core:web:local.host:users:alice",
            "ak:did_core:web:local.host:users:alice",
            "alice:local.host",
            &participants,
        ),
        "alice:local.host"
    );
}

#[test]
fn participant_display_name_prefers_local_remark() {
    let participants = vec![SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap(),
        display_name: Some("Bobby".to_owned()),
        handle_label: None,
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    }];

    assert_eq!(
        sender_display_label(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:alice.example",
            "Alice",
            &participants,
        ),
        "Bobby"
    );
    assert_eq!(
        sender_display_label(
            "ak:did_core:web:carol.example",
            "ak:did_core:web:alice.example",
            "Alice",
            &participants
        ),
        crate::views::helpers::short_protocol_id("ak:did_core:web:carol.example")
    );
}

#[test]
fn sender_display_label_does_not_invent_domain_for_localpart() {
    let participants = vec![SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:local.host:users:alice".to_owned(),
        )
        .unwrap(),
        display_name: Some("alice".to_owned()),
        handle_label: None,
        display_name_rank: 2,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    }];

    assert_eq!(
        sender_display_label(
            "ak:did_core:web:local.host:users:alice",
            "ak:did_core:web:local.host:users:alice",
            "alice",
            &participants,
        ),
        "alice"
    );
}

#[test]
fn own_sender_label_prefers_account_handle_over_did_derived_materialized_id() {
    let participants = vec![SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:auth.local.host:users:01ktwstvaef1dby1xf5mnkxss8".to_owned(),
        )
        .unwrap(),
        display_name: None,
        handle_label: None,
        display_name_rank: u8::MAX,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    }];

    assert_eq!(
        sender_display_label(
            "ak:did_core:web:auth.local.host:users:01ktwstvaef1dby1xf5mnkxss8",
            "ak:did_core:web:auth.local.host:users:01ktwstvaef1dby1xf5mnkxss8",
            "alice:local.host",
            &participants,
        ),
        "alice:local.host"
    );
}

#[test]
fn sender_display_label_prefers_projection_handle_label() {
    let participants = vec![SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:bob".to_owned(),
        )
        .unwrap(),
        display_name: Some("bob".to_owned()),
        handle_label: Some("bob:example.com".to_owned()),
        display_name_rank: 2,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    }];

    assert_eq!(
        sender_display_label(
            "ak:did_core:web:example.com:users:bob",
            "ak:did_core:web:local.host:users:alice",
            "alice:local.host",
            &participants,
        ),
        "bob:example.com"
    );
}

#[test]
fn account_handle_requires_a_complete_verified_handle() {
    assert_eq!(normalize_account_handle("alice"), None);
    assert_eq!(
        normalize_account_handle("alice:example.com").as_deref(),
        Some("alice:example.com")
    );
    assert_eq!(normalize_account_handle("  "), None);
}

#[test]
fn participant_roster_ignores_noncanonical_identity_fields() {
    let projection = json!({
        "member_roster_entries": [
            {
                "did": "ak:did_core:web:bob.example",
                "display_name": "Bob Example",
                "remark": "Bob from ops"
            }
        ]
    });
    let temp = std::env::temp_dir().join(format!("inkson-chat-roster-{}", uuid_v7()));
    let store = LocalStateStore::with_path(temp);
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "ak:did_core:web:alice.example",
    );
    assert_eq!(participants.len(), 1);
    assert!(participants[0].is_self);
}

#[test]
fn participant_roster_rejects_naked_handle_field() {
    let projection = json!({
        "member_roster_entries": [
            {
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:example.com:users:bob","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join",
                "handle": "bob:example.com"
            }
        ]
    });

    let temp = std::env::temp_dir().join(format!("inkson-chat-roster-{}", uuid_v7()));
    let store = LocalStateStore::with_path(temp);
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "ak:did_core:web:alice.example",
    );
    // §3.8 forbids a naked handle string on the roster entry. The entry is a
    // closed wire type, so the row is rejected outright rather than rendered
    // with the naked field quietly ignored.
    assert!(!participants.iter().any(|participant| {
        participant.principal_id.as_str() == "ak:did_core:web:example.com:users:bob"
    }));
}

#[test]
fn extracts_participant_handle_label_from_inline_handle_claims() {
    let bob_subject = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
    );
    let mut projection = json!({
        "member_roster_entries": [
            {
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join",
                "subject_account_id": bob_subject,
                "handle_claims": [crate::views::member_display::test_handle_claim(
                    &bob_subject,
                    "bob:local.host",
                    "ak:did_core:web:local.host",
                    arkret_models_identity::HandleClaimStatus::Verified,
                )]
            }
        ]
    });
    projection["current"] = json!([arkret_wire::TypedCurrentResult::Value {
        selector: arkret_wire::CurrentSelector::RealmPolicy,
        revision: arkret_wire::CurrentRevision {
            commit_id: arkret_sdk::RealmCommitId::from_digest([0x41; 32]),
            stream_position: 1,
        },
        value: json!({
            "policy_revision": 1,
            "handle_issuer_policies": [{
                "issuer_id": "ak:did_core:web:local.host",
                "authorized_handle_domains": ["local.host"],
                "issuer_class": "domain_authority"
            }]
        }),
    }]);

    let temp = std::env::temp_dir().join(format!("inkson-chat-roster-{}", uuid_v7()));
    let store = LocalStateStore::with_path(temp);
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "ak:did_core:web:alice.example",
    );
    let bob = participants
        .iter()
        .find(|participant| participant.principal_id.as_str() == "ak:did_core:web:bob.example")
        .unwrap();

    assert_eq!(
        mention_label_for_participant(bob).as_deref(),
        Some("bob:local.host")
    );
}
