use super::*;

/// A Realm-authorized, accepted interaction row identifies its exact Agent
/// account independently of the viewer's private inventory. Labels remain
/// unresolved; the composer still re-reads current mode before offering it.
pub(crate) fn annotate_agents_from_current(
    participants: &mut [SpaceParticipant],
    view: Option<&crate::current_projection::RealmCurrentView>,
    realm_id: &str,
) {
    let Some(view) = view.filter(|view| view.complete_cut && view.realm_id == realm_id) else {
        return;
    };
    for row in &view.entries {
        let arkret_wire::CurrentState::Value {
            selector: arkret_wire::CurrentSelector::AgentInteraction { agent_account_id },
            source_stream_ref:
                arkret_wire::CommitStreamRef::Realm {
                    realm_id: source_realm,
                },
            value,
            ..
        } = row
        else {
            continue;
        };
        if source_realm.as_str() != realm_id
            || serde_json::from_value::<arkret_sdk::AgentInteractionCurrentValue>(value.clone())
                .is_err()
        {
            continue;
        }
        for participant in participants.iter_mut() {
            if participant
                .actor_id
                .as_ref()
                .and_then(arkret_sdk::ActorId::as_account_id)
                == Some(agent_account_id)
            {
                participant.is_agent = true;
            }
        }
    }
}

#[cfg(test)]
#[test]
fn public_agent_identity_uses_exact_authorized_current_without_private_inventory() {
    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let agent = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:public-agent.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let remote = arkret_sdk::AccountId::new(
        agent.principal_id.clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    );
    let controller = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
        agent.station_id.clone(),
    );
    let mut ordinary = Vec::new();
    for account in [&agent, &remote] {
        upsert_participant(
            &mut ordinary,
            &arkret_sdk::ActorId::account(account.clone()),
            SpaceParticipantRole::Member,
            "ak:did_core:web:caller.example",
            None,
            None,
        );
    }
    let row = arkret_wire::CurrentState::Value {
        selector: arkret_wire::CurrentSelector::AgentInteraction {
            agent_account_id: agent.clone(),
        },
        source_stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
        },
        revision: arkret_sdk::CurrentRevision {
            commit_id: arkret_sdk::RealmCommitId::from_digest([1; 32]),
            stream_position: 1,
        },
        value: serde_json::to_value(arkret_sdk::AgentInteractionCurrentValue {
            controller_account_id: controller,
            interaction_mode: arkret_sdk::AgentInteractionMode::Public,
        })
        .unwrap(),
    };
    let view = crate::current_projection::RealmCurrentView::new(REALM, vec![row], true).unwrap();
    let mut participants = ordinary.clone();
    annotate_agents_from_current(&mut participants, Some(&view), REALM);
    let participant = participants
        .iter()
        .find(|p| participant_mention_account(p).as_ref() == Some(&agent))
        .unwrap();
    assert!(participant.is_agent);
    assert!(participant.agent_metadata.is_none());
    let candidate = mention_candidate_for_participant(
        participant,
        &participants,
        "ak:did_core:web:caller.example",
    )
    .unwrap();
    assert_eq!(candidate.subject_account_id, agent);
    assert!(candidate.is_agent);
    assert!(candidate.agent_slug_at_time.is_empty());
    assert!(!agent_candidate_is_visible(
        participant,
        &Default::default(),
        "ak:did_core:web:caller.example"
    ));
    assert!(agent_candidate_is_visible(
        participant,
        &std::collections::BTreeSet::from([arkret_sdk::ActorId::account(agent).to_string()]),
        "ak:did_core:web:caller.example"
    ));
    assert!(
        !participants
            .iter()
            .find(|p| participant_mention_account(p).as_ref() == Some(&remote))
            .unwrap()
            .is_agent
    );
    let mut incomplete = view.clone();
    incomplete.complete_cut = false;
    let mut wrong_stream = view.clone();
    let arkret_wire::CurrentState::Value {
        source_stream_ref, ..
    } = &mut wrong_stream.entries[0];
    *source_stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_sdk::RealmId::new("ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM")
            .unwrap(),
    };
    let mut malformed = view.clone();
    let arkret_wire::CurrentState::Value { value, .. } = &mut malformed.entries[0];
    *value = serde_json::json!({"interaction_mode":"public"});
    for invalid in [&incomplete, &wrong_stream, &malformed] {
        let mut participants = ordinary.clone();
        annotate_agents_from_current(&mut participants, Some(invalid), REALM);
        assert!(participants.iter().all(|p| !p.is_agent));
    }
    let mut participants = ordinary;
    annotate_agents_from_current(&mut participants, Some(&view), "another Realm");
    assert!(participants.iter().all(|p| !p.is_agent));
}

pub(crate) fn merge_agent_metadata(
    existing: &mut AgentParticipantMetadata,
    next: AgentParticipantMetadata,
) {
    if existing.controller_principal_id.is_empty() {
        existing.controller_principal_id = next.controller_principal_id;
    }
    if existing.controller_handle.is_empty() {
        existing.controller_handle = next.controller_handle;
    }
    if existing.agent_slug.is_empty() {
        existing.agent_slug = next.agent_slug;
    }
    if existing.display_name.is_empty() {
        existing.display_name = next.display_name;
    }
}

pub(crate) fn participation_allows_public_reply(
    entries: &[arkret_models_collaboration::governance::agent_participation::AgentParticipationView],
    realm_id: &str,
    circle_id: Option<&str>,
    strand_id: &str,
) -> bool {
    let strand_match = entries.iter().find(|entry| {
        matches!(
            &entry.target_scope,
            arkret_models_collaboration::governance::agent_participation::ParticipationScope::Strand {
                realm_id: entry_realm,
                strand_id: entry_strand,
            } if entry_realm.as_str() == realm_id && entry_strand.as_str() == strand_id
        )
    });
    let realm_match = entries.iter().find(|entry| {
        matches!(
            &entry.target_scope,
            arkret_models_collaboration::governance::agent_participation::ParticipationScope::Realm {
                realm_id: entry_realm,
            } if entry_realm.as_str() == realm_id
        )
    });
    let circle_match = circle_id.and_then(|circle_id| {
        entries.iter().find(|entry| {
            matches!(
                &entry.target_scope,
                arkret_models_collaboration::governance::agent_participation::ParticipationScope::Circle {
                    realm_id: entry_realm,
                    circle_id: entry_circle,
                } if entry_realm.as_str() == realm_id && entry_circle.as_str() == circle_id
            )
        })
    });
    strand_match
        .or(circle_match)
        .or(realm_match)
        .is_some_and(|entry| entry.selection.message_creation_allowed)
}

pub(crate) fn agent_metadata_from_mentions(
    messages: &[ChatMessage],
) -> std::collections::BTreeMap<String, AgentParticipantMetadata> {
    let mut out = std::collections::BTreeMap::new();
    for mention in messages
        .iter()
        .flat_map(|message| message.mentions.iter())
        .filter_map(MentionNode::as_mention)
    {
        let agent_slug = mention.agent_slug_at_time.as_deref().unwrap_or_default();
        let Some(controller_subject_account_id) = mention.controller_subject_account_id.as_ref()
        else {
            continue;
        };
        if agent_slug.is_empty() || arkret_models_identity::validate_agent_slug(agent_slug).is_err()
        {
            continue;
        }
        // This map only ever enriches the selected account's own Agent
        // inventory, which lives at this client's authoring Station. A mention
        // whose subject or controller is hosted elsewhere carries no metadata
        // for that inventory and is skipped.
        let Ok(local_station) = crate::operation::authoring_station_id() else {
            continue;
        };
        if mention.subject_account_id.station_id != local_station
            || controller_subject_account_id.station_id != local_station
        {
            continue;
        }
        let next = AgentParticipantMetadata {
            controller_principal_id: controller_subject_account_id
                .principal_id
                .as_str()
                .to_owned(),
            controller_handle: mention
                .controller_handle_at_time
                .as_ref()
                .and_then(|handle| crate::identity::handle::parse_user_handle(handle.canonical()))
                .map(|parsed| parsed.handle)
                .unwrap_or_default(),
            agent_slug: agent_slug.trim().to_owned(),
            display_name: clean_participant_display_name(
                mention.display_name_at_time.as_deref().unwrap_or_default(),
                Some(mention.subject_account_id.principal_id.as_str()),
            )
            .unwrap_or_default(),
        };
        out.entry(mention.subject_account_id.principal_id.as_str().to_owned())
            .and_modify(|existing| merge_agent_metadata(existing, next.clone()))
            .or_insert(next);
    }
    out
}

pub(crate) fn enrich_authoritative_agent_metadata(
    authoritative: &mut std::collections::BTreeMap<String, AgentParticipantMetadata>,
    audit_metadata: std::collections::BTreeMap<String, AgentParticipantMetadata>,
) {
    for (agent_id, metadata) in audit_metadata {
        if let Some(existing) = authoritative.get_mut(&agent_id) {
            merge_agent_metadata(existing, metadata);
        }
    }
}

pub(crate) fn upsert_joined_owned_agent_participants(
    participants: &mut Vec<SpaceParticipant>,
    joined_members: Option<&std::collections::BTreeSet<arkret_sdk::ActorId>>,
    agent_metadata: &std::collections::BTreeMap<String, AgentParticipantMetadata>,
    principal_id: &str,
) {
    let Some(joined_members) = joined_members else {
        return;
    };
    let Ok(station) = crate::operation::authoring_station_id() else {
        return;
    };
    // Inventory supplies Agent identity; the complete verified member current
    // supplies its hosted Account. A partial display roster cannot supply both.
    for actor in joined_members {
        let Some(account) = actor.as_account_id() else {
            continue;
        };
        if account.station_id != station
            || !agent_metadata.contains_key(account.principal_id.as_str())
        {
            continue;
        }
        upsert_participant(
            participants,
            actor,
            SpaceParticipantRole::Member,
            principal_id,
            None,
            None,
        );
    }
}

pub(crate) fn upsert_agent_participants(
    participants: &mut Vec<SpaceParticipant>,
    agent_metadata: &std::collections::BTreeMap<String, AgentParticipantMetadata>,
    principal_id: &str,
) {
    for (agent_id, metadata) in agent_metadata {
        let Some(agent_principal_id) = normalize_participant_id(agent_id) else {
            continue;
        };
        if participants.iter().any(|participant| {
            participant.principal_id == agent_principal_id
                && owned_agent_inventory_matches(participant)
        }) {
            continue;
        }
        participants.push(SpaceParticipant {
            actor_id: None,
            principal_id: agent_principal_id,
            display_name: (!metadata.display_name.is_empty())
                .then_some(metadata.display_name.clone()),
            handle_label: None,
            display_name_rank: if metadata.display_name.is_empty() {
                u8::MAX
            } else {
                1
            },
            role: SpaceParticipantRole::Member,
            is_self: agent_id == principal_id,
            is_agent: true,
            agent_metadata: Some(metadata.clone()),
        });
    }
}

/// This metadata map belongs to the selected account's owned-Agent inventory.
/// Its principal labels cannot identify a hosted actor at another Station.
fn owned_agent_inventory_matches(participant: &SpaceParticipant) -> bool {
    match participant.actor_id.as_ref() {
        None => true, // Inventory-only display row, never a membership identity.
        Some(arkret_sdk::ActorId::Account {
            account_id: arkret_sdk::AccountId { station_id, .. },
        }) => crate::operation::authoring_station_id().is_ok_and(|local| local == *station_id),
        Some(_) => false,
    }
}

pub(crate) fn annotate_agent_participants_with_metadata(
    participants: &mut [SpaceParticipant],
    agent_metadata: &std::collections::BTreeMap<String, AgentParticipantMetadata>,
) {
    for participant in participants.iter_mut() {
        if !owned_agent_inventory_matches(participant) {
            continue;
        }
        if let Some(metadata) = agent_metadata.get(participant.principal_id.as_str()) {
            participant.is_agent = true;
            participant.agent_metadata = Some(metadata.clone());
            if participant.display_name.is_none() && !metadata.display_name.is_empty() {
                participant.display_name = Some(metadata.display_name.clone());
                participant.display_name_rank = 1;
            }
        }
    }
}

pub(crate) fn owned_agent_metadata(
    agent_slugs: &std::collections::BTreeMap<String, String>,
    controller_principal_id: &str,
    controller_handle: Option<&str>,
) -> std::collections::BTreeMap<String, AgentParticipantMetadata> {
    let controller_principal_id = controller_principal_id.trim();
    if controller_principal_id.is_empty() {
        return std::collections::BTreeMap::new();
    }
    let controller_handle = controller_handle.unwrap_or_default().trim();
    agent_slugs
        .iter()
        .filter_map(|(agent_id, slug)| {
            let agent_id = agent_id.trim();
            let slug = slug.trim();
            if agent_id.is_empty()
                || slug.is_empty()
                || arkret_models_identity::validate_agent_slug(slug).is_err()
            {
                return None;
            }
            Some((
                agent_id.to_owned(),
                AgentParticipantMetadata {
                    controller_principal_id: controller_principal_id.to_owned(),
                    controller_handle: controller_handle.to_owned(),
                    agent_slug: slug.to_owned(),
                    display_name: slug.to_owned(),
                },
            ))
        })
        .collect()
}
