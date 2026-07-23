use super::*;

pub(crate) fn normalize_participant_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(crate) fn clean_participant_display_name(value: &str, did: Option<&str>) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") || did == Some(trimmed) {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(crate) fn mention_handle_label_from_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }
    crate::identity::handle::parse_user_handle(trimmed).map(|handle| handle.display)
}

pub(crate) fn mention_label_for_participant(participant: &SpaceParticipant) -> Option<String> {
    participant.handle_label.clone().or_else(|| {
        participant
            .display_name
            .as_deref()
            .and_then(mention_handle_label_from_value)
    })
}

pub(crate) fn upsert_participant(
    participants: &mut Vec<SpaceParticipant>,
    did: &str,
    role: SpaceParticipantRole,
    account_did: &str,
    display_name: Option<(String, u8)>,
    handle_label: Option<String>,
) {
    let Some(did) = normalize_participant_id(did) else {
        return;
    };
    let is_self = did == account_did;
    if let Some(existing) = participants
        .iter_mut()
        .find(|candidate| candidate.did == did)
    {
        existing.is_self |= is_self;
        if let Some((display_name, rank)) = display_name
            && (existing.display_name.is_none() || rank < existing.display_name_rank)
        {
            existing.display_name = Some(display_name);
            existing.display_name_rank = rank;
        }
        if existing.handle_label.is_none() {
            existing.handle_label = handle_label;
        }
    } else {
        let (display_name, display_name_rank) = display_name
            .map(|(name, rank)| (Some(name), rank))
            .unwrap_or((None, u8::MAX));
        participants.push(SpaceParticipant {
            did,
            display_name,
            handle_label,
            display_name_rank,
            role,
            is_self,
            // Default; the caller annotates agent DIDs via
            // `annotate_agent_participants` after the projection-based
            // upsert pass completes.
            is_agent: false,
            agent_metadata: None,
        });
    }
}

pub(crate) fn participant_roster_rows(
    participants: &[SpaceParticipant],
    visible_agent_dids: &std::collections::BTreeSet<String>,
) -> Vec<ParticipantRosterRow> {
    let visible_dids = participants
        .iter()
        .map(|participant| participant.did.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut agents_by_controller =
        std::collections::BTreeMap::<String, Vec<SpaceParticipant>>::new();
    for participant in participants
        .iter()
        .filter(|participant| participant.is_agent && visible_agent_dids.contains(&participant.did))
    {
        let Some(metadata) = participant.agent_metadata.as_ref() else {
            continue;
        };
        if metadata.controller_id.is_empty()
            || !visible_dids.contains(metadata.controller_id.as_str())
        {
            continue;
        }
        agents_by_controller
            .entry(metadata.controller_id.clone())
            .or_default()
            .push(participant.clone());
    }

    for agents in agents_by_controller.values_mut() {
        agents.sort_by(|left, right| {
            agent_member_label(left)
                .cmp(&agent_member_label(right))
                .then(left.did.cmp(&right.did))
        });
    }

    let grouped_agent_dids = agents_by_controller
        .values()
        .flatten()
        .map(|agent| agent.did.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let mut rows = Vec::new();
    for participant in participants {
        if participant.is_agent && !visible_agent_dids.contains(&participant.did) {
            continue;
        }
        if grouped_agent_dids.contains(participant.did.as_str()) {
            continue;
        }
        if let Some(agents) = agents_by_controller.get(&participant.did)
            && !agents.is_empty()
        {
            rows.push(ParticipantRosterRow::ControllerWithAgents {
                controller: participant.clone(),
                agents: agents.clone(),
            });
            continue;
        }
        rows.push(ParticipantRosterRow::Participant(participant.clone()));
    }
    // Keep the local controller at the top even if a caller assembled the
    // participant slice from multiple projections with a different order.
    // The roster contract is stable across the presence list, member list,
    // and mention picker: the current account is always first.
    rows.sort_by_key(|row| {
        let is_self = match row {
            ParticipantRosterRow::Participant(participant) => participant.is_self,
            ParticipantRosterRow::ControllerWithAgents { controller, .. } => controller.is_self,
        };
        !is_self
    });
    rows
}

pub(crate) fn space_participants(
    projection: Option<&Value>,
    state_store: &LocalStateStore,
    realm_id: &str,
    account_did: &str,
) -> Vec<SpaceParticipant> {
    let mut participants = Vec::new();

    for row in crate::views::member_display::realm_member_roster(projection) {
        let is_self = row.actor_id.trim() == account_did.trim()
            || row.subject_id.as_deref().map(str::trim) == Some(account_did.trim());
        let display =
            crate::views::member_display::resolve_member_display(state_store, realm_id, &row);
        upsert_participant(
            &mut participants,
            &row.actor_id,
            SpaceParticipantRole::Member,
            account_did,
            display.display_name.map(|name| (name, 1)),
            display.primary_handle,
        );
        if is_self
            && let Some(participant) = participants
                .iter_mut()
                .find(|participant| participant.did == row.actor_id)
        {
            participant.is_self = true;
        }
    }

    if !account_did.trim().is_empty() && !participants.iter().any(|participant| participant.is_self)
    {
        let account_handle = state_store
            .primary_handle_for_did(account_did)
            .and_then(|handle| mention_handle_label_from_value(&handle));
        upsert_participant(
            &mut participants,
            account_did,
            SpaceParticipantRole::Member,
            account_did,
            None,
            account_handle,
        );
    }

    participants.sort_by(|left, right| {
        right
            .is_self
            .cmp(&left.is_self)
            .then_with(|| left.did.cmp(&right.did))
    });
    participants
}

pub(crate) fn display_label_for_actor(
    state_store: &LocalStateStore,
    participants: &[SpaceParticipant],
    live_labels: &std::collections::BTreeMap<String, String>,
    did: &str,
) -> String {
    if let Some(label) = live_labels
        .get(did)
        .and_then(|label| clean_participant_display_name(label, Some(did)))
    {
        return label;
    }
    participants
        .iter()
        .find(|participant| participant.did == did)
        .and_then(participant_sender_label)
        .unwrap_or_else(|| crate::views::helpers::actor_display_label(state_store, did))
}

pub(crate) fn is_own_message_sender(sender: &str, account_did: &str) -> bool {
    let sender = sender.trim();
    !sender.is_empty() && (sender == "inkson" || sender == account_did.trim())
}

pub(crate) fn short_principal_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "Unknown".to_owned();
    }
    let principal = trimmed.strip_prefix("did:web:").unwrap_or(trimmed);
    let tail = principal.rsplit(':').next().unwrap_or(principal);
    // Count / slice by characters, not bytes: a display name or handle with
    // non-ASCII would otherwise slice mid-character and panic the render.
    if tail.chars().count() > 18 {
        let head: String = tail.chars().take(8).collect();
        let tail_len = tail.chars().count();
        let suffix: String = tail.chars().skip(tail_len - 6).collect();
        format!("{head}...{suffix}")
    } else {
        tail.to_owned()
    }
}

pub(crate) fn agent_display_label(participant: &SpaceParticipant) -> String {
    participant
        .agent_metadata
        .as_ref()
        .and_then(|metadata| {
            (!metadata.display_name.trim().is_empty()).then_some(metadata.display_name.clone())
        })
        .or_else(|| participant.display_name.clone())
        .or_else(|| participant_handle_label(participant))
        .unwrap_or_else(|| short_principal_label(&participant.did))
}

pub(crate) fn agent_member_label(participant: &SpaceParticipant) -> String {
    participant
        .agent_metadata
        .as_ref()
        .map(|metadata| metadata.agent_slug.trim())
        .filter(|slug| !slug.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| agent_display_label(participant))
}

pub(crate) fn sidecar_owned_agent_participants(
    participants: &[SpaceParticipant],
    account_did: &str,
) -> Vec<SpaceParticipant> {
    participants
        .iter()
        .filter(|participant| {
            participant.is_agent
                && participant
                    .agent_metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.controller_id.trim() == account_did.trim())
        })
        .cloned()
        .collect()
}

pub(crate) fn sidecar_presence_participants(
    participants: &[SpaceParticipant],
    account_did: &str,
) -> Vec<SpaceParticipant> {
    participants
        .iter()
        .filter(|participant| {
            participant.did.trim() == account_did.trim()
                || (participant.is_agent
                    && participant.agent_metadata.as_ref().is_some_and(|metadata| {
                        metadata.controller_id.trim() == account_did.trim()
                    }))
        })
        .cloned()
        .collect()
}

pub(crate) fn participant_sender_label(participant: &SpaceParticipant) -> Option<String> {
    if participant.is_agent {
        return Some(agent_member_label(participant));
    }
    participant_handle_label(participant).or_else(|| participant.display_name.clone())
}

pub(crate) fn participant_handle_label(participant: &SpaceParticipant) -> Option<String> {
    participant.handle_label.clone()
}

pub(crate) fn participant_roster_display_label(
    state_store: &LocalStateStore,
    participant: &SpaceParticipant,
) -> String {
    if participant.is_agent {
        return agent_member_label(participant);
    }
    participant_sender_label(participant).unwrap_or_else(|| {
        crate::views::helpers::actor_display_label(state_store, &participant.did)
    })
}

pub(crate) fn agent_controller_label(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
) -> Option<String> {
    let metadata = participant.agent_metadata.as_ref()?;
    participants
        .iter()
        .find(|candidate| candidate.did == metadata.controller_id)
        .and_then(participant_sender_label)
        .or_else(|| {
            (!metadata.controller_handle.trim().is_empty())
                .then(|| metadata.controller_handle.clone())
        })
        .or_else(|| {
            (!metadata.controller_id.trim().is_empty())
                .then(|| short_principal_label(&metadata.controller_id))
        })
}

pub(crate) fn agent_selector_label(participant: &SpaceParticipant) -> Option<String> {
    let metadata = participant.agent_metadata.as_ref()?;
    if metadata.controller_handle.trim().is_empty() || metadata.agent_slug.trim().is_empty() {
        return None;
    }
    Some(format!(
        "{}/{}",
        metadata.controller_handle.trim(),
        metadata.agent_slug.trim()
    ))
}

pub(crate) fn mention_candidate_for_participant(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
    account_did: &str,
) -> Option<crate::messaging::mentions::MentionCandidate> {
    if participant.is_agent {
        let display_name = agent_display_label(participant);
        let metadata = participant.agent_metadata.as_ref();
        let selector = metadata.and_then(|metadata| {
            if metadata.agent_slug.trim().is_empty() {
                None
            } else if metadata.controller_id.trim() == account_did.trim() {
                Some(format!("me/{}", metadata.agent_slug.trim()))
            } else {
                agent_selector_label(participant)
            }
        });
        let controller_label = agent_controller_label(participant, participants);
        return Some(crate::messaging::mentions::MentionCandidate {
            did: participant.did.clone(),
            display_name,
            insert_label: selector.unwrap_or_else(|| {
                mention_label_for_participant(participant)
                    .unwrap_or_else(|| short_principal_label(&participant.did))
            }),
            subtitle: controller_label
                .map(|label| format!("agent of {label}"))
                .unwrap_or_else(|| "agent".to_owned()),
            is_agent: true,
            controller_subject_id: metadata
                .map(|metadata| metadata.controller_id.clone())
                .unwrap_or_default(),
            controller_handle_at_time: metadata
                .map(|metadata| metadata.controller_handle.clone())
                .unwrap_or_default(),
            agent_slug_at_time: metadata
                .map(|metadata| metadata.agent_slug.clone())
                .unwrap_or_default(),
        });
    }

    if participant.is_self {
        let display_name = participant_sender_label(participant)
            .unwrap_or_else(|| short_principal_label(&participant.did));
        return Some(crate::messaging::mentions::MentionCandidate {
            did: participant.did.clone(),
            display_name,
            insert_label: "me".to_owned(),
            subtitle: "You".to_owned(),
            is_agent: false,
            controller_subject_id: String::new(),
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        });
    }

    let handle_label = mention_label_for_participant(participant)?;
    let display_name = handle_label.clone();
    Some(crate::messaging::mentions::MentionCandidate {
        did: participant.did.clone(),
        display_name,
        insert_label: handle_label,
        subtitle: String::new(),
        is_agent: false,
        controller_subject_id: String::new(),
        controller_handle_at_time: String::new(),
        agent_slug_at_time: String::new(),
    })
}

pub(crate) fn mention_candidate_for_explicit_target(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
    account_did: &str,
    public_agent_dids: &std::collections::BTreeSet<String>,
    requested_agent_slug: Option<&str>,
    own_controller_handle: Option<&str>,
) -> Option<crate::messaging::mentions::MentionCandidate> {
    if requested_agent_slug.is_some() {
        return owned_agent_mention_candidate(
            &participant.did,
            requested_agent_slug,
            account_did,
            own_controller_handle,
        );
    }
    if !agent_candidate_is_visible(participant, public_agent_dids, account_did) {
        return None;
    }
    mention_candidate_for_participant(participant, participants, account_did).or_else(|| {
        let fallback_label = participant_sender_label(participant)
            .unwrap_or_else(|| short_principal_label(&participant.did));
        Some(crate::messaging::mentions::MentionCandidate {
            did: participant.did.clone(),
            display_name: fallback_label.clone(),
            insert_label: fallback_label,
            subtitle: String::new(),
            is_agent: false,
            controller_subject_id: String::new(),
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        })
    })
}

pub(crate) fn owned_agent_mention_candidate(
    agent_id: &str,
    requested_agent_slug: Option<&str>,
    account_did: &str,
    own_controller_handle: Option<&str>,
) -> Option<crate::messaging::mentions::MentionCandidate> {
    let agent_slug = requested_agent_slug
        .map(str::trim)
        .filter(|slug| arkret_models_identity::validate_agent_slug(slug).is_ok())?;
    let agent_id = agent_id.trim();
    let account_did = account_did.trim();
    if agent_id.is_empty() || account_did.is_empty() {
        return None;
    }
    Some(crate::messaging::mentions::MentionCandidate {
        did: agent_id.to_owned(),
        display_name: agent_slug.to_owned(),
        insert_label: format!("me/{agent_slug}"),
        subtitle: "Your agent".to_owned(),
        is_agent: true,
        controller_subject_id: account_did.to_owned(),
        controller_handle_at_time: own_controller_handle
            .map(str::trim)
            .filter(|handle| !handle.is_empty())
            .unwrap_or_default()
            .to_owned(),
        agent_slug_at_time: agent_slug.to_owned(),
    })
}

pub(crate) fn agent_candidate_is_visible(
    participant: &SpaceParticipant,
    public_agent_dids: &std::collections::BTreeSet<String>,
    account_did: &str,
) -> bool {
    if !participant.is_agent {
        return true;
    }
    public_agent_dids.contains(&participant.did)
        || participant
            .agent_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.controller_id.trim() == account_did.trim())
}

pub(crate) fn readable_participation_agent_ids(
    participants: &[SpaceParticipant],
    account_did: &str,
) -> Vec<String> {
    let account_did = account_did.trim();
    let mut agent_ids = participants
        .iter()
        .filter(|participant| participant.is_agent)
        .filter(|participant| {
            participant
                .agent_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.controller_id.trim() == account_did)
        })
        .map(|participant| participant.did.clone())
        .collect::<Vec<_>>();
    agent_ids.sort();
    agent_ids.dedup();
    agent_ids
}

pub(crate) fn sender_display_label(
    sender: &str,
    account_did: &str,
    account_display_name: &str,
    participants: &[SpaceParticipant],
) -> String {
    if is_own_message_sender(sender, account_did) {
        let account_did = account_did.trim();
        let own_participant = participants
            .iter()
            .find(|participant| participant.is_self && !participant.is_agent);
        let account_display_name =
            clean_participant_display_name(account_display_name, Some(account_did));
        let participant_display_name =
            own_participant.and_then(|participant| participant.display_name.clone());
        return own_participant
            .and_then(|participant| participant.handle_label.clone())
            .or(account_display_name)
            .or(participant_display_name)
            .unwrap_or_else(|| {
                if account_did.is_empty() {
                    "inkson".to_owned()
                } else {
                    crate::views::helpers::short_protocol_id(account_did)
                }
            });
    }
    participants
        .iter()
        .find(|participant| participant.did == sender.trim())
        .and_then(participant_sender_label)
        .unwrap_or_else(|| crate::views::helpers::short_protocol_id(sender))
}

/// AKP-0008 §4.10 — resolve the agent label for an act-on-behalf
/// message. Returns the agent's display label when `executed_by` is a
/// distinct agent principal from `actor_id` (the controller); otherwise
/// returns `None` (ordinary message or reply-as-agent, where the sender
/// itself is the agent). The caller renders "{controller} via {agent}"
/// with the controller as the primary name.
pub(crate) fn act_on_behalf_agent_label(
    sender: &str,
    executed_by: Option<&str>,
    participants: &[SpaceParticipant],
) -> Option<String> {
    let executed_by = executed_by
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if executed_by == sender.trim() {
        return None;
    }
    let agent_participant = participants
        .iter()
        .find(|participant| participant.did == executed_by);
    match agent_participant {
        Some(participant) if participant.is_agent => Some(agent_display_label(participant)),
        // The executor is not a known agent participant — fall back to a
        // short principal label so the "via" attribution still renders.
        Some(_) => None,
        None => Some(short_principal_label(executed_by)),
    }
}
