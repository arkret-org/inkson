//! Mention-candidate construction and handle resolution.

use super::*;

#[test]
fn mention_candidate_for_own_agent_uses_me_alias() {
    let controller = SpaceParticipant {
        actor_id: Some(local_fixture_actor(
            "ak:did_core:web:example.com:users:alice",
        )),
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:alice".to_owned(),
        )
        .unwrap(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };
    let agent = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:agents.example:summary".to_owned(),
        )
        .unwrap(),
        display_name: Some("Summary Assistant".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_principal_id: controller.principal_id.to_string(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Summary Assistant".to_owned(),
        }),
    };
    let participants = vec![controller.clone(), agent.clone()];
    let candidate =
        mention_candidate_for_participant(&agent, &participants, controller.principal_id.as_str())
            .expect("agent mention candidate");
    assert_eq!(candidate.display_name, "Summary Assistant");
    assert_eq!(candidate.insert_label(), "me/summary");
    assert_eq!(
        candidate.subject_account_id,
        local_fixture_account("ak:did_core:web:agents.example:summary")
    );
    assert_eq!(
        candidate.controller_subject_account_id,
        Some(local_fixture_account(
            "ak:did_core:web:example.com:users:alice"
        ))
    );
    assert_eq!(candidate.controller_handle_at_time, "alice:example.com");
    assert_eq!(candidate.agent_slug_at_time, "summary");
}

#[test]
fn mention_candidate_for_current_user_uses_structured_me_alias() {
    let participant = SpaceParticipant {
        actor_id: Some(local_fixture_actor(
            "ak:did_core:web:example.com:users:alice",
        )),
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:alice".to_owned(),
        )
        .unwrap(),
        display_name: Some("Alice".to_owned()),
        handle_label: None,
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };

    let candidate = mention_candidate_for_participant(
        &participant,
        std::slice::from_ref(&participant),
        participant.principal_id.as_str(),
    )
    .expect("current-user mention candidate");
    assert_eq!(
        candidate.subject_account_id,
        local_fixture_account(participant.principal_id.as_str())
    );
    assert_eq!(candidate.insert_label(), "me");
    assert_eq!(candidate.subtitle, "You");

    let mentions = composer_mention_nodes(
        true,
        "ping @me",
        std::slice::from_ref(&candidate),
        participant.principal_id.as_str(),
    );
    let mention = mentions[0].as_mention().expect("structured self mention");
    assert_eq!(
        mention.subject_account_id,
        local_fixture_account("ak:did_core:web:example.com:users:alice")
    );
    assert_eq!(mention.mention_text_original.as_deref(), Some("@me"));

    let typed_mentions =
        composer_mention_nodes(true, "ping @me", &[], participant.principal_id.as_str());
    let typed_mention = typed_mentions[0]
        .as_mention()
        .expect("typed structured self mention");
    assert_eq!(
        typed_mention.subject_account_id,
        local_fixture_account("ak:did_core:web:example.com:users:alice")
    );
    assert_eq!(typed_mention.mention_text_original.as_deref(), Some("@me"));

    assert!(
        composer_mention_nodes(
            true,
            "ask @me/summary",
            &[],
            participant.principal_id.as_str(),
        )
        .is_empty()
    );
}

#[test]
fn resolved_owned_agent_chip_suppresses_duplicate_directory_lookup() {
    let controller = "ak:did_core:web:example.com:users:alice";
    let mention = arkret_sdk::Mention::new(local_fixture_account(
        "ak:did_core:web:agents.example:summary",
    ))
    .with_agent_selector_metadata(
        local_fixture_account(controller),
        arkret_sdk::Handle::parse("alice:example.com").unwrap(),
        "summary",
    )
    .with_mention_text_original("@me/summary");
    let mentions = vec![MentionNode::mention(mention)];
    let owned = parse_agent_selector_mention_tokens("ask @me/summary")
        .into_iter()
        .next()
        .unwrap();
    let remote = parse_agent_selector_mention_tokens("ask @alice:example.com/summary")
        .into_iter()
        .next()
        .unwrap();
    let unresolved = parse_agent_selector_mention_tokens("ask @me/digest")
        .into_iter()
        .next()
        .unwrap();

    assert!(agent_selector_mention_is_already_resolved(
        &mentions, &owned, controller
    ));
    assert!(agent_selector_mention_is_already_resolved(
        &mentions, &remote, controller
    ));
    assert!(!agent_selector_mention_is_already_resolved(
        &mentions,
        &unresolved,
        controller
    ));
}

#[test]
fn owned_agent_inventory_enriches_existing_realm_member_metadata() {
    let slugs = std::collections::BTreeMap::from([(
        "ak:did_core:web:agents.example:summary".to_owned(),
        "summary".to_owned(),
    )]);
    let metadata = owned_agent_metadata(
        &slugs,
        "ak:did_core:web:example.com:users:alice",
        Some("alice:example.com"),
    );
    let summary = metadata
        .get("ak:did_core:web:agents.example:summary")
        .expect("owned agent metadata");
    assert_eq!(
        summary.controller_principal_id,
        "ak:did_core:web:example.com:users:alice"
    );
    assert_eq!(summary.controller_handle, "alice:example.com");
    assert_eq!(summary.agent_slug, "summary");
}

#[test]
fn explicit_member_click_builds_user_and_owned_agent_mentions() {
    let principal_id = "ak:did_core:web:example.com:users:alice";
    let member = SpaceParticipant {
        actor_id: Some(local_fixture_actor("ak:did_core:web:example.com:users:bob")),
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:bob".to_owned(),
        )
        .unwrap(),
        display_name: Some("Bob".to_owned()),
        handle_label: None,
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };
    let clicked_member = mention_candidate_for_explicit_target(
        &member,
        std::slice::from_ref(&member),
        principal_id,
        &std::collections::BTreeSet::new(),
        None,
        Some("alice:example.com"),
    )
    .expect("explicit member mention");
    assert_eq!(
        clicked_member.subject_account_id,
        local_fixture_account(member.principal_id.as_str())
    );
    assert!(!clicked_member.is_agent);

    let unannotated_owned_agent = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:agents.example:summary".to_owned(),
        )
        .unwrap(),
        display_name: None,
        handle_label: None,
        display_name_rank: u8::MAX,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };
    let clicked_agent = mention_candidate_for_explicit_target(
        &unannotated_owned_agent,
        std::slice::from_ref(&unannotated_owned_agent),
        principal_id,
        &std::collections::BTreeSet::new(),
        Some("summary"),
        Some("alice:example.com"),
    )
    .expect("explicit owned-agent mention");
    assert_eq!(clicked_agent.insert_label(), "me/summary");
    assert!(clicked_agent.is_agent);
    assert_eq!(
        clicked_agent.controller_subject_account_id,
        Some(local_fixture_account(principal_id))
    );
    assert_eq!(clicked_agent.agent_slug_at_time, "summary");

    let before_handle_load = owned_agent_mention_candidate(
        unannotated_owned_agent.principal_id.as_str(),
        Some("summary"),
        principal_id,
        None,
    )
    .expect("@me selector must not wait for the account handle");
    assert_eq!(before_handle_load.insert_label(), "me/summary");
    assert!(before_handle_load.controller_handle_at_time.is_empty());
    assert!(
        composer_mention_nodes(
            true,
            "ask @me/summary",
            std::slice::from_ref(&before_handle_load),
            principal_id,
        )
        .is_empty()
    );
}

#[test]
fn mention_candidate_for_other_agent_keeps_canonical_controller_handle() {
    let controller = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:bob".to_owned(),
        )
        .unwrap(),
        display_name: Some("Bob".to_owned()),
        handle_label: Some("bob:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };
    let agent = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:agents.example:summary".to_owned(),
        )
        .unwrap(),
        display_name: Some("Summary Assistant".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_principal_id: controller.principal_id.to_string(),
            controller_handle: "bob:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Summary Assistant".to_owned(),
        }),
    };
    let participants = vec![controller, agent.clone()];

    let candidate = mention_candidate_for_participant(
        &agent,
        &participants,
        "ak:did_core:web:example.com:users:alice",
    )
    .expect("agent mention candidate");

    assert_eq!(candidate.insert_label(), "bob:example.com/summary");
}

#[test]
fn agent_candidate_visibility_keeps_owned_agents_and_hides_private_remote_agents() {
    let own_controller = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:alice".to_owned(),
        )
        .unwrap(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };
    let own_agent = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:agents.example:alice-summary".to_owned(),
        )
        .unwrap(),
        display_name: Some("Alice Summary".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_principal_id: own_controller.principal_id.to_string(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Alice Summary".to_owned(),
        }),
    };
    let remote_agent = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:agents.example:bob-summary".to_owned(),
        )
        .unwrap(),
        display_name: Some("Bob Summary".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_principal_id: "ak:did_core:web:example.com:users:bob".to_owned(),
            controller_handle: "bob:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Bob Summary".to_owned(),
        }),
    };
    let principal_id = own_controller.principal_id.as_str();
    let visible = std::collections::BTreeSet::new();

    assert!(agent_candidate_is_visible(
        &own_agent,
        &visible,
        principal_id
    ));
    assert!(!agent_candidate_is_visible(
        &remote_agent,
        &visible,
        principal_id
    ));
    assert!(agent_candidate_is_visible(
        &remote_agent,
        &std::collections::BTreeSet::from([remote_agent.principal_id.to_string()]),
        principal_id
    ));
    let sidecar_mentions = sidecar_owned_agent_participants(
        &[
            own_controller.clone(),
            own_agent.clone(),
            remote_agent.clone(),
        ],
        principal_id,
    );
    assert_eq!(sidecar_mentions, vec![own_agent.clone()]);
    assert_eq!(
        readable_participation_agent_ids(&[own_agent.clone(), remote_agent], principal_id),
        vec![own_agent.principal_id.to_string()]
    );
}

#[test]
fn sidecar_presence_excludes_realm_humans_and_foreign_agents() {
    let controller = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:alice".to_owned(),
        )
        .unwrap(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };
    let realm_human = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:bob".to_owned(),
        )
        .unwrap(),
        display_name: Some("Bob".to_owned()),
        handle_label: Some("bob:example.com".to_owned()),
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };
    let owned_agent = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:agents.example:alice-summary".to_owned(),
        )
        .unwrap(),
        display_name: Some("Alice Summary".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_principal_id: controller.principal_id.to_string(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Alice Summary".to_owned(),
        }),
    };
    let foreign_agent = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:agents.example:bob-summary".to_owned(),
        )
        .unwrap(),
        display_name: Some("Bob Summary".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_principal_id: realm_human.principal_id.to_string(),
            controller_handle: "bob:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Bob Summary".to_owned(),
        }),
    };

    let visible = sidecar_presence_participants(
        &[
            controller.clone(),
            realm_human,
            owned_agent.clone(),
            foreign_agent,
        ],
        controller.principal_id.as_str(),
    );

    assert_eq!(visible, vec![controller, owned_agent]);
}

#[test]
fn mention_candidate_without_handle_is_not_displayed_as_did() {
    let participant = SpaceParticipant {
        actor_id: Some(local_fixture_actor("ak:did_core:web:bob.example")),
        principal_id: arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap(),
        display_name: Some("Bob Example".to_owned()),
        handle_label: None,
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };

    assert!(
        mention_candidate_for_participant(
            &participant,
            std::slice::from_ref(&participant),
            "ak:did_core:web:alice.example",
        )
        .is_none()
    );
}

#[test]
fn mention_candidate_uses_cached_member_handle() {
    let temp = std::env::temp_dir().join(format!("inkson-chat-mention-handle-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let bob_account = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    );
    store.save_member_handle_lookup(
        &bob_account,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned()),
        None,
        Some("bob:local.host".to_owned()),
        1,
        None,
        None,
    );
    let projection = json!({"member_roster_entries": [{
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
        "membership": "join",
        "subject_account_id": {"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}
    }]});
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "ak:did_core:web:alice.example",
    );
    let bob = participants
        .iter()
        .find(|participant| participant.principal_id.as_str() == "ak:did_core:web:bob.example")
        .expect("bob participant");
    let candidate =
        mention_candidate_for_participant(bob, &participants, "ak:did_core:web:alice.example")
            .expect("member mention candidate");
    assert_eq!(
        candidate.subject_account_id,
        local_fixture_account("ak:did_core:web:bob.example")
    );
    assert_eq!(candidate.display_name, "bob:local.host");
    assert_eq!(candidate.insert_label(), "bob:local.host");
    assert_eq!(candidate.subtitle, "");
}

#[test]
fn late_join_discussion_sender_resolves_cached_member_handle() {
    let sender = "ak:did_core:web:history.example:alice";
    let realm = "ak:realm:AhbOTVxMlBQEJeDfw_EHOeGGCT2uJ17cMT4QctC7CaFI";
    let temp = std::env::temp_dir().join(format!("inkson-chat-late-join-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let sender_account = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new(sender).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    );
    store.save_member_handle_lookup(
        &sender_account,
        Some(realm.to_owned()),
        None,
        Some("alice:local.host".to_owned()),
        1,
        None,
        None,
    );
    let projection = json!({"member_roster_entries": [{
        "actor_id": {"kind": "account", "account_id": {
            "principal_id": sender,
            "station_id": "ak:did_core:web:principal.example"
        }},
        "membership": "join",
        "subject_account_id": {
            "principal_id": sender,
            "station_id": "ak:did_core:web:principal.example"
        }
    }]});
    let participants = space_participants(
        Some(&projection),
        &store,
        realm,
        "ak:did_core:web:reader.example",
    );

    assert_eq!(
        sender_display_label(
            sender,
            "ak:did_core:web:reader.example",
            "reader:local.host",
            &participants,
        ),
        "alice:local.host"
    );
}

#[test]
fn unresolved_historical_sender_uses_the_shared_protocol_id_fallback() {
    let sender = "ak:did_core:webvh:zQmHistoricalAuthor0123456789abcdefghijk";
    assert_eq!(
        sender_display_label(sender, "ak:did_core:web:alice.example", "Alice", &[]),
        crate::views::helpers::short_protocol_id(sender)
    );
}

/// `identity-handles.md` §3.8 — a mention chip carries the complete account.
/// The same principal joined from another Station is a different subject, so
/// the two candidates never collapse and neither one can be built without a
/// resolvable Station.
#[test]
fn mention_candidate_keeps_same_principal_accounts_at_different_stations_apart() {
    let principal = "ak:did_core:web:bob.example";
    let local = SpaceParticipant {
        actor_id: Some(local_fixture_actor(principal)),
        principal_id: arkret_sdk::DidCoreId::new(principal.to_owned()).unwrap(),
        display_name: None,
        handle_label: Some("bob:local.host".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };
    let remote = SpaceParticipant {
        actor_id: Some(arkret_sdk::ActorId::account(fixture_account(
            principal,
            REMOTE_STATION_ID,
        ))),
        ..local.clone()
    };
    let participants = vec![local.clone(), remote.clone()];
    let requester = "ak:did_core:web:alice.example";

    let local_candidate = mention_candidate_for_participant(&local, &participants, requester)
        .expect("local member mention candidate");
    let remote_candidate = mention_candidate_for_participant(&remote, &participants, requester)
        .expect("remote member mention candidate");

    assert_eq!(
        local_candidate.subject_account_id.principal_id,
        remote_candidate.subject_account_id.principal_id
    );
    assert_ne!(
        local_candidate.subject_account_id,
        remote_candidate.subject_account_id
    );

    // Inserting one chip must not hide the other, and the composer must emit
    // two distinct mention nodes.
    let mut picker = crate::messaging::mentions::MentionPickerState::new();
    assert!(picker.insert(local_candidate.clone()));
    let candidates = [local_candidate.clone(), remote_candidate.clone()];
    let offered = picker.filter(&candidates);
    assert_eq!(offered.len(), 1);
    assert_eq!(
        offered[0].subject_account_id,
        remote_candidate.subject_account_id
    );

    let mentions = composer_mention_nodes(
        true,
        "ping both",
        &[local_candidate.clone(), remote_candidate.clone()],
        requester,
    );
    let subjects = mentions
        .iter()
        .filter_map(MentionNode::as_mention)
        .map(|mention| mention.subject_account_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        subjects,
        vec![
            local_candidate.subject_account_id,
            remote_candidate.subject_account_id
        ]
    );
}

/// A roster row without a membership identity is not an owned-Agent inventory
/// row, so its Station is unknown: it MUST NOT become a mention chip rather
/// than be completed by guessing a Station.
#[test]
fn mention_candidate_fails_closed_without_a_resolvable_account() {
    let participant = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap(),
        display_name: None,
        handle_label: Some("bob:local.host".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };

    assert!(participant_mention_account(&participant).is_none());
    assert!(
        mention_candidate_for_participant(
            &participant,
            std::slice::from_ref(&participant),
            "ak:did_core:web:alice.example",
        )
        .is_none()
    );
    assert!(
        mention_candidate_for_explicit_target(
            &participant,
            std::slice::from_ref(&participant),
            "ak:did_core:web:alice.example",
            &std::collections::BTreeSet::new(),
            None,
            None,
        )
        .is_none()
    );
}
