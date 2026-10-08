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
fn current_only_self_participant_keeps_the_account_viewer_handle_without_leaking_to_remote() {
    let principal = "ak:did_core:web:current-self-handle.example";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let own = crate::mls_api_helpers::local_account_actor_id(principal).unwrap();
    let remote = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        own.signing_principal_id().clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap(),
    ));
    let account = crate::test_support::AccountFixture::new(principal)
        .station(own.as_account_id().unwrap().station_id.as_str())
        .build();
    let directory = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(directory.path().join("self-handle.json"));
    store.switch_active_account(&account).unwrap();
    let handle = "alice:local.host";
    store.set_primary_handle_for_principal_id(principal, handle);
    let entries =
        [own.clone(), remote.clone()].map(|actor| arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::MemberState { actor_id: actor },
            source_stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.parse().unwrap(),
            },
            revision: arkret_wire::CurrentRevision {
                commit_id: arkret_sdk::RealmCommitId::from_digest([0x42; 32]),
                stream_position: 2,
            },
            value: json!({"membership":"join","joined_at":"2026-10-08T00:00:00.000Z"}),
        });
    store
        .install_current_product_view(
            crate::current_projection::RealmCurrentView::new(realm, entries.to_vec(), true)
                .unwrap(),
        )
        .unwrap();
    let participants = space_participants(None, &store, realm, principal);
    assert_eq!(participants.len(), 2);
    let own_row = participants
        .iter()
        .find(|row| row.actor_id.as_ref() == Some(&own))
        .unwrap();
    assert!(own_row.is_self);
    assert_eq!(own_row.handle_label.as_deref(), Some(handle));
    assert_eq!(
        sender_display_label(principal, principal, "", &participants),
        handle
    );
    let remote_row = participants
        .iter()
        .find(|row| row.actor_id.as_ref() == Some(&remote))
        .unwrap();
    assert!(!remote_row.is_self);
    assert!(remote_row.handle_label.is_none());

    let mut departed = entries.to_vec();
    let arkret_wire::TypedCurrentResult::Value { value, .. } = &mut departed[0];
    *value = json!({"membership":"leave"});
    store
        .install_current_product_view(
            crate::current_projection::RealmCurrentView::new(realm, departed, true).unwrap(),
        )
        .unwrap();
    let remaining = space_participants(None, &store, realm, principal);
    assert_eq!(remaining.len(), 1);
    assert!(!remaining[0].is_self);
    assert!(remaining[0].handle_label.is_none());
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
    let projection = json!({
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
    const POLICY_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let policy = arkret_wire::TypedCurrentResult::Value {
        selector: arkret_wire::CurrentSelector::RealmPolicyBundle,
        source_stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(POLICY_REALM).unwrap(),
        },
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
    };

    let temp = std::env::temp_dir().join(format!("inkson-chat-roster-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let membership = arkret_wire::TypedCurrentResult::Value {
        selector: arkret_wire::CurrentSelector::MemberState {
            actor_id: arkret_sdk::ActorId::account(bob_subject),
        },
        source_stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: POLICY_REALM.parse().unwrap(),
        },
        revision: arkret_wire::CurrentRevision {
            commit_id: arkret_sdk::RealmCommitId::from_digest([0x41; 32]),
            stream_position: 1,
        },
        value: json!({"membership":"join","joined_at":"2026-10-08T00:00:00.000Z"}),
    };
    crate::test_support::install_current_entries(
        &mut store,
        POLICY_REALM,
        vec![policy, membership],
    );
    let participants = space_participants(
        Some(&projection),
        &store,
        POLICY_REALM,
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
