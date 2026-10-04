//! Effective-scope participation visibility and roster grouping.

use super::*;

#[test]
fn participation_visibility_uses_most_specific_effective_scope() {
    use arkret_models_collaboration::governance::agent_participation::{
        AgentParticipationEntry, ParticipationBits, ParticipationNextReplaceInput,
        ParticipationScope,
    };

    let realm = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
    let circle = "ak:circle:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let realm_entry = AgentParticipationEntry {
        scope: ParticipationScope::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
        selection: ParticipationBits::ALL,
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    };
    let circle_entry = AgentParticipationEntry {
        scope: ParticipationScope::Circle {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
            circle_id: arkret_sdk::CircleId::new(circle.to_owned()).unwrap(),
        },
        selection: ParticipationBits::NONE,
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    };

    assert!(participation_allows_public_reply(
        std::slice::from_ref(&realm_entry),
        realm,
        None,
        "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
    ));
    assert!(!participation_allows_public_reply(
        &[realm_entry, circle_entry],
        realm,
        Some(circle),
        "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
    ));
}

#[test]
fn participation_visibility_can_target_an_authoritative_discussion_strand() {
    use arkret_models_collaboration::governance::agent_participation::{
        AgentParticipationEntry, ParticipationBits, ParticipationNextReplaceInput,
        ParticipationScope,
    };

    let realm = "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";
    let strand = "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned();
    let entry = AgentParticipationEntry {
        scope: ParticipationScope::Strand {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
            strand_id: arkret_sdk::StrandId::new(strand.clone()).unwrap(),
        },
        selection: ParticipationBits::ALL,
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    };

    assert!(participation_allows_public_reply(
        std::slice::from_ref(&entry),
        realm,
        None,
        &strand,
    ));
}

#[test]
fn mention_only_participation_does_not_expose_agent_in_roster() {
    use arkret_models_collaboration::governance::agent_participation::{
        AgentParticipationEntry, ParticipationBits, ParticipationNextReplaceInput,
        ParticipationScope,
    };

    let realm = "ak:realm:AUuXpUO-yBwwyCNB7AS1IIm5_sgsxyEsG7PBmmkXdFog";
    let mention_only = ParticipationBits {
        reply_message: false,
        reaction_add: false,
        reaction_remove: false,
        accept_third_party_mention: true,
        act_on_behalf: false,
    };
    let entry = AgentParticipationEntry {
        scope: ParticipationScope::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
        selection: mention_only,
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    };

    assert!(!participation_allows_public_reply(
        std::slice::from_ref(&entry),
        realm,
        None,
        "ak:strand:AYdzR-cxE5CaMt7Xeab7lJ6oTMVcXRDFIfPqcXOahgQ4",
    ));
}

#[test]
fn participant_roster_rows_groups_agents_under_visible_controller() {
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
    let visible = std::collections::BTreeSet::from([agent.roster_key()]);
    assert_eq!(
        participant_roster_display_label(&crate::state::LocalStateStore::default(), &controller,),
        "alice:example.com"
    );
    assert_eq!(
        participant_roster_display_label(&crate::state::LocalStateStore::default(), &agent,),
        "summary"
    );
    let rows = participant_roster_rows(&[controller.clone(), agent.clone()], &visible);
    assert_eq!(rows.len(), 1);
    match &rows[0] {
        ParticipantRosterRow::ControllerWithAgents { controller, agents } => {
            assert_eq!(
                controller.principal_id.as_str(),
                "ak:did_core:web:example.com:users:alice"
            );
            assert_eq!(agents.len(), 1);
            assert_eq!(
                agents[0].principal_id.as_str(),
                "ak:did_core:web:agents.example:summary"
            );
        }
        ParticipantRosterRow::Participant(_) => panic!("expected grouped controller row"),
    }

    let private_rows = participant_roster_rows(
        &[controller.clone(), agent],
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(
        private_rows,
        vec![ParticipantRosterRow::Participant(controller)]
    );
}

#[test]
fn direct_agent_peer_visibility_does_not_require_reply_participation() {
    let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:example.com:agents:aa").unwrap();
    let agent = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        principal.clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
    ))
    .to_string();
    let other_station = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        principal,
        arkret_sdk::DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
    ))
    .to_string();
    let projected_members = std::collections::BTreeSet::from([agent.clone()]);
    assert!(direct_agent_is_conversation_peer(
        &agent,
        "",
        &projected_members
    ));
    assert!(direct_agent_is_conversation_peer(
        &agent,
        &agent,
        &std::collections::BTreeSet::new()
    ));
    assert!(!direct_agent_is_conversation_peer(
        &other_station,
        &agent,
        &projected_members
    ));
}
