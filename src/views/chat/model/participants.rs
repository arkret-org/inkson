use super::*;

pub(crate) fn normalize_participant_id(value: &str) -> Option<String> {
    arkret_sdk::DidCoreId::new(value.trim().to_owned())
        .ok()
        .map(|principal_id| principal_id.to_string())
}

pub(crate) fn clean_participant_display_name(
    value: &str,
    principal_id: Option<&str>,
) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") || principal_id == Some(trimmed) {
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
    participant_id: &str,
    role: SpaceParticipantRole,
    own_principal_id: &str,
    display_name: Option<(String, u8)>,
    handle_label: Option<String>,
) {
    let Some(principal_id) = normalize_participant_id(participant_id) else {
        return;
    };
    let is_self = same_principal_core(&principal_id, own_principal_id);
    if let Some(existing) = participants
        .iter_mut()
        .find(|candidate| same_principal_core(&candidate.principal_id, &principal_id))
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
            principal_id,
            display_name,
            handle_label,
            display_name_rank,
            role,
            is_self,
            // Default; the caller annotates agent IDs via
            // `annotate_agent_participants` after the projection-based
            // upsert pass completes.
            is_agent: false,
            agent_metadata: None,
        });
    }
}

pub(crate) fn participant_roster_rows(
    participants: &[SpaceParticipant],
    visible_agent_ids: &std::collections::BTreeSet<String>,
) -> Vec<ParticipantRosterRow> {
    let visible_principal_ids = participants
        .iter()
        .map(|participant| participant.principal_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut agents_by_controller =
        std::collections::BTreeMap::<String, Vec<SpaceParticipant>>::new();
    for participant in participants.iter().filter(|participant| {
        participant.is_agent
            && visible_agent_ids
                .iter()
                .any(|visible| same_principal_core(visible, &participant.principal_id))
    }) {
        let Some(metadata) = participant.agent_metadata.as_ref() else {
            continue;
        };
        let Some(controller_id) = visible_principal_ids
            .iter()
            .find(|visible| same_principal_core(visible, &metadata.controller_id))
        else {
            continue;
        };
        agents_by_controller
            .entry((*controller_id).to_owned())
            .or_default()
            .push(participant.clone());
    }

    for agents in agents_by_controller.values_mut() {
        agents.sort_by(|left, right| {
            agent_member_label(left)
                .cmp(&agent_member_label(right))
                .then(left.principal_id.cmp(&right.principal_id))
        });
    }

    let grouped_agent_ids = agents_by_controller
        .values()
        .flatten()
        .map(|agent| agent.principal_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let mut rows = Vec::new();
    for participant in participants {
        if participant.is_agent
            && !visible_agent_ids
                .iter()
                .any(|visible| same_principal_core(visible, &participant.principal_id))
        {
            continue;
        }
        if grouped_agent_ids.contains(participant.principal_id.as_str()) {
            continue;
        }
        if let Some(agents) = agents_by_controller.get(&participant.principal_id)
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

pub(crate) fn direct_agent_is_conversation_peer(
    agent_id: &str,
    direct_peer_id: &str,
    projected_member_ids: &std::collections::BTreeSet<String>,
) -> bool {
    !agent_id.trim().is_empty()
        && (agent_id == direct_peer_id || projected_member_ids.contains(agent_id))
}

pub(crate) fn space_participants(
    projection: Option<&Value>,
    state_store: &LocalStateStore,
    realm_id: &str,
    principal_id: &str,
) -> Vec<SpaceParticipant> {
    let mut participants = Vec::new();

    for row in crate::views::member_display::realm_member_roster(projection) {
        let is_self = same_principal_core(&row.actor_id, principal_id)
            || row
                .subject_id
                .as_deref()
                .is_some_and(|subject| same_principal_core(subject, principal_id));
        let display =
            crate::views::member_display::resolve_member_display(state_store, realm_id, &row);
        upsert_participant(
            &mut participants,
            &row.actor_id,
            SpaceParticipantRole::Member,
            principal_id,
            display.display_name.map(|name| (name, 1)),
            display.primary_handle,
        );
        if is_self
            && let Some(participant) = participants
                .iter_mut()
                .find(|participant| participant.principal_id == row.actor_id)
        {
            participant.is_self = true;
        }
    }

    if !principal_id.trim().is_empty()
        && !participants.iter().any(|participant| participant.is_self)
    {
        let account_handle = state_store
            .primary_handle_for_principal_id(principal_id)
            .and_then(|handle| mention_handle_label_from_value(&handle));
        upsert_participant(
            &mut participants,
            principal_id,
            SpaceParticipantRole::Member,
            principal_id,
            None,
            account_handle,
        );
    }

    participants.sort_by(|left, right| {
        right
            .is_self
            .cmp(&left.is_self)
            .then_with(|| left.principal_id.cmp(&right.principal_id))
    });
    participants
}

pub(crate) fn display_label_for_actor(
    state_store: &LocalStateStore,
    participants: &[SpaceParticipant],
    live_labels: &std::collections::BTreeMap<String, String>,
    actor_id: &str,
) -> String {
    if let Some(label) = live_labels
        .get(actor_id)
        .and_then(|label| clean_participant_display_name(label, Some(actor_id)))
    {
        return label;
    }
    participants
        .iter()
        .find(|participant| participant.principal_id == actor_id)
        .and_then(participant_sender_label)
        .unwrap_or_else(|| crate::views::helpers::actor_display_label(state_store, actor_id))
}

pub(crate) fn is_own_message_sender(sender: &str, principal_id: &str) -> bool {
    let sender = sender.trim();
    if sender.is_empty() {
        return false;
    }
    let principal_id = principal_id.trim();
    if sender == "inkson" || sender == principal_id {
        return true;
    }
    false
}

pub(crate) fn short_principal_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "Unknown".to_owned();
    }
    let tail = trimmed.rsplit(':').next().unwrap_or(trimmed);
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
        .unwrap_or_else(|| short_principal_label(&participant.principal_id))
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
    principal_id: &str,
) -> Vec<SpaceParticipant> {
    participants
        .iter()
        .filter(|participant| {
            participant.is_agent
                && participant
                    .agent_metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.controller_id.trim() == principal_id.trim())
        })
        .cloned()
        .collect()
}

pub(crate) fn sidecar_presence_participants(
    participants: &[SpaceParticipant],
    principal_id: &str,
) -> Vec<SpaceParticipant> {
    participants
        .iter()
        .filter(|participant| {
            participant.principal_id.trim() == principal_id.trim()
                || (participant.is_agent
                    && participant.agent_metadata.as_ref().is_some_and(|metadata| {
                        metadata.controller_id.trim() == principal_id.trim()
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
        crate::views::helpers::actor_display_label(state_store, &participant.principal_id)
    })
}

pub(crate) fn agent_controller_label(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
) -> Option<String> {
    let metadata = participant.agent_metadata.as_ref()?;
    participants
        .iter()
        .find(|candidate| candidate.principal_id == metadata.controller_id)
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
    principal_id: &str,
) -> Option<crate::messaging::mentions::MentionCandidate> {
    if participant.is_agent {
        let display_name = agent_display_label(participant);
        let metadata = participant.agent_metadata.as_ref();
        let selector = metadata.and_then(|metadata| {
            if metadata.agent_slug.trim().is_empty() {
                None
            } else if same_principal_core(&metadata.controller_id, principal_id) {
                Some(format!("me/{}", metadata.agent_slug.trim()))
            } else {
                agent_selector_label(participant)
            }
        });
        let controller_label = agent_controller_label(participant, participants);
        return Some(crate::messaging::mentions::MentionCandidate {
            subject_id: participant.principal_id.clone(),
            display_name,
            insert_label: selector.unwrap_or_else(|| {
                mention_label_for_participant(participant)
                    .unwrap_or_else(|| short_principal_label(&participant.principal_id))
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
            .unwrap_or_else(|| short_principal_label(&participant.principal_id));
        return Some(crate::messaging::mentions::MentionCandidate {
            subject_id: participant.principal_id.clone(),
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
        subject_id: participant.principal_id.clone(),
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
    principal_id: &str,
    public_agent_ids: &std::collections::BTreeSet<String>,
    requested_agent_slug: Option<&str>,
    own_controller_handle: Option<&str>,
) -> Option<crate::messaging::mentions::MentionCandidate> {
    if requested_agent_slug.is_some() {
        return owned_agent_mention_candidate(
            &participant.principal_id,
            requested_agent_slug,
            principal_id,
            own_controller_handle,
        );
    }
    if !agent_candidate_is_visible(participant, public_agent_ids, principal_id) {
        return None;
    }
    mention_candidate_for_participant(participant, participants, principal_id).or_else(|| {
        let fallback_label = participant_sender_label(participant)
            .unwrap_or_else(|| short_principal_label(&participant.principal_id));
        Some(crate::messaging::mentions::MentionCandidate {
            subject_id: participant.principal_id.clone(),
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
    principal_id: &str,
    own_controller_handle: Option<&str>,
) -> Option<crate::messaging::mentions::MentionCandidate> {
    let agent_slug = requested_agent_slug
        .map(str::trim)
        .filter(|slug| arkret_models_identity::validate_agent_slug(slug).is_ok())?;
    let agent_id = agent_id.trim();
    let principal_id = principal_id.trim();
    if agent_id.is_empty() || principal_id.is_empty() {
        return None;
    }
    Some(crate::messaging::mentions::MentionCandidate {
        subject_id: agent_id.to_owned(),
        display_name: agent_slug.to_owned(),
        insert_label: format!("me/{agent_slug}"),
        subtitle: "Your agent".to_owned(),
        is_agent: true,
        controller_subject_id: principal_id.to_owned(),
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
    public_agent_ids: &std::collections::BTreeSet<String>,
    principal_id: &str,
) -> bool {
    if !participant.is_agent {
        return true;
    }
    public_agent_ids.contains(&participant.principal_id)
        || participant
            .agent_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.controller_id.trim() == principal_id.trim())
}

pub(crate) fn readable_participation_agent_ids(
    participants: &[SpaceParticipant],
    principal_id: &str,
) -> Vec<String> {
    let principal_id = principal_id.trim();
    let mut agent_ids = participants
        .iter()
        .filter(|participant| participant.is_agent)
        .filter(|participant| {
            participant
                .agent_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.controller_id.trim() == principal_id)
        })
        .map(|participant| participant.principal_id.clone())
        .collect::<Vec<_>>();
    agent_ids.sort();
    agent_ids.dedup();
    agent_ids
}

pub(crate) fn sender_display_label(
    sender: &str,
    principal_id: &str,
    account_display_name: &str,
    participants: &[SpaceParticipant],
) -> String {
    if is_own_message_sender(sender, principal_id) {
        let principal_id = principal_id.trim();
        let own_participant = participants
            .iter()
            .find(|participant| participant.is_self && !participant.is_agent);
        let account_display_name =
            clean_participant_display_name(account_display_name, Some(principal_id));
        let participant_display_name =
            own_participant.and_then(|participant| participant.display_name.clone());
        return own_participant
            .and_then(|participant| participant.handle_label.clone())
            .or(account_display_name)
            .or(participant_display_name)
            .unwrap_or_else(|| {
                if principal_id.is_empty() {
                    "inkson".to_owned()
                } else {
                    crate::views::helpers::short_protocol_id(principal_id)
                }
            });
    }
    participants
        .iter()
        .find(|participant| participant.principal_id == sender.trim())
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
        .find(|participant| participant.principal_id == executed_by);
    match agent_participant {
        Some(participant) if participant.is_agent => Some(agent_display_label(participant)),
        // The executor is not a known agent participant — fall back to a
        // short principal label so the "via" attribution still renders.
        Some(_) => None,
        None => Some(short_principal_label(executed_by)),
    }
}
