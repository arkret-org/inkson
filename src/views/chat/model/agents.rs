use super::*;

pub(crate) fn merge_agent_metadata(
    existing: &mut AgentParticipantMetadata,
    next: AgentParticipantMetadata,
) {
    if existing.controller_id.is_empty() {
        existing.controller_id = next.controller_id;
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
    entries: &[arkret_models_collaboration::governance::agent_participation::AgentParticipationEntry],
    realm_id: &str,
    circle_id: Option<&str>,
    strand_id: &str,
) -> bool {
    let strand_match = entries.iter().find(|entry| {
        matches!(
            &entry.scope,
            arkret_models_collaboration::governance::agent_participation::AgentParticipationScope::Strand {
                realm_id: entry_realm,
                strand_id: entry_strand,
            } if entry_realm.as_str() == realm_id && entry_strand.as_str() == strand_id
        )
    });
    let realm_match = entries.iter().find(|entry| {
        matches!(
            &entry.scope,
            arkret_models_collaboration::governance::agent_participation::AgentParticipationScope::Realm {
                realm_id: entry_realm,
            } if entry_realm.as_str() == realm_id
        )
    });
    let circle_match = circle_id.and_then(|circle_id| {
        entries.iter().find(|entry| {
            matches!(
                &entry.scope,
                arkret_models_collaboration::governance::agent_participation::AgentParticipationScope::Circle {
                    realm_id: entry_realm,
                    circle_id: entry_circle,
                } if entry_realm.as_str() == realm_id && entry_circle.as_str() == circle_id
            )
        })
    });
    strand_match
        .or(circle_match)
        .or(realm_match)
        .is_some_and(|entry| entry.effective.reply)
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
        let Some(controller_subject_id) = mention.controller_subject_id.as_ref() else {
            continue;
        };
        if agent_slug.is_empty()
            || controller_subject_id.as_str().trim().is_empty()
            || arkret_models_identity::validate_agent_slug(agent_slug).is_err()
        {
            continue;
        }
        let next = AgentParticipantMetadata {
            controller_id: controller_subject_id.as_str().trim().to_owned(),
            controller_handle: mention
                .controller_handle_at_time
                .as_ref()
                .and_then(|handle| crate::identity::handle::parse_user_handle(handle.canonical()))
                .map(|parsed| parsed.handle)
                .unwrap_or_default(),
            agent_slug: agent_slug.trim().to_owned(),
            display_name: clean_participant_display_name(
                mention.display_name_at_time.as_deref().unwrap_or_default(),
                Some(mention.subject_id.as_str()),
            )
            .unwrap_or_default(),
        };
        out.entry(mention.subject_id.as_str().trim().to_owned())
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

pub(crate) fn upsert_agent_participants(
    participants: &mut Vec<SpaceParticipant>,
    agent_metadata: &std::collections::BTreeMap<String, AgentParticipantMetadata>,
    account_did: &str,
) {
    for (agent_id, metadata) in agent_metadata {
        if participants
            .iter()
            .any(|participant| participant.did == *agent_id)
        {
            continue;
        }
        participants.push(SpaceParticipant {
            did: agent_id.clone(),
            display_name: (!metadata.display_name.is_empty())
                .then_some(metadata.display_name.clone()),
            handle_label: None,
            display_name_rank: if metadata.display_name.is_empty() {
                u8::MAX
            } else {
                1
            },
            role: SpaceParticipantRole::Member,
            is_self: agent_id == account_did,
            is_agent: true,
            agent_metadata: Some(metadata.clone()),
        });
    }
}

pub(crate) fn annotate_agent_participants_with_metadata(
    participants: &mut [SpaceParticipant],
    agent_metadata: &std::collections::BTreeMap<String, AgentParticipantMetadata>,
) {
    for participant in participants.iter_mut() {
        if let Some(metadata) = agent_metadata.get(&participant.did) {
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
    controller_id: &str,
    controller_handle: Option<&str>,
) -> std::collections::BTreeMap<String, AgentParticipantMetadata> {
    let controller_id = controller_id.trim();
    if controller_id.is_empty() {
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
                    controller_id: controller_id.to_owned(),
                    controller_handle: controller_handle.to_owned(),
                    agent_slug: slug.to_owned(),
                    display_name: slug.to_owned(),
                },
            ))
        })
        .collect()
}
