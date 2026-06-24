use super::*;

pub(crate) fn normalize_participant_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(crate) fn participant_id_from_state_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some(index) = trimmed.find("did:") {
        normalize_participant_id(&trimmed[index..])
    } else {
        None
    }
}

pub(crate) fn participant_role_from_str(
    value: Option<&str>,
    fallback: SpaceParticipantRole,
) -> SpaceParticipantRole {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "owner" => SpaceParticipantRole::Owner,
        "admin" | "administrator" => SpaceParticipantRole::Admin,
        _ => fallback,
    }
}

pub(crate) fn participant_id_from_value(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_str() {
        return normalize_participant_id(raw);
    }

    let object = value.as_object()?;
    [
        "did",
        "account_did",
        "member",
        "user",
        "actor",
        "actor_id",
        "subject",
        "state_key",
        "id",
        "identifier",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(participant_id_from_value))
}

pub(crate) fn participant_id_from_member_value(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_str() {
        return normalize_participant_id(raw);
    }

    let object = value.as_object()?;
    [
        "did",
        "account_did",
        "member",
        "user",
        "actor",
        "actor_id",
        "subject",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(participant_id_from_member_value))
}

pub(crate) fn clean_participant_display_name(value: &str, did: Option<&str>) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") || did == Some(trimmed) {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(crate) fn participant_display_name_from_value(
    value: &Value,
    did: Option<&str>,
) -> Option<(String, u8)> {
    let object = value.as_object()?;
    for (rank, keys) in [
        (
            0,
            ["remark", "note", "local_name", "contact_name"].as_slice(),
        ),
        (
            1,
            [
                "display_name",
                "displayName",
                "nickname",
                "alias",
                "preferred_name",
            ]
            .as_slice(),
        ),
        (2, ["name", "handle", "username"].as_slice()),
    ] {
        if let Some(name) = keys
            .iter()
            .find_map(|key| object.get(*key).and_then(Value::as_str))
            .and_then(|raw| clean_participant_display_name(raw, did))
        {
            return Some((name, rank));
        }
    }

    [
        "profile", "account", "member", "user", "actor", "subject", "details",
    ]
    .iter()
    .find_map(|key| {
        object
            .get(*key)
            .filter(|child| child.is_object())
            .and_then(|child| participant_display_name_from_value(child, did))
    })
}

pub(crate) fn mention_handle_label_from_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }
    crate::identity_handle::parse_user_handle(trimmed).map(|handle| handle.display)
}

pub(crate) fn participant_handle_label_from_value(
    value: &Value,
    did: Option<&str>,
) -> Option<String> {
    let object = value.as_object()?;
    if let Some(label) = participant_inline_handle_claim_label(object.get("handle_claims"), did) {
        return Some(label);
    }
    // R3.1 wire rename: spec field is `handle`. Older payloads may
    // still ship `handle_uri` (cokret:// URI form retired @ 7157ee8);
    // accept both for migration compatibility.
    [
        "handle",
        "handle_uri",
        "handleUri",
        "user_handle",
        "userHandle",
        "acct_alias",
        "acctAlias",
        "acct",
        "mxid",
    ]
    .iter()
    .find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .filter(|raw| did != Some(raw.trim()))
            .and_then(mention_handle_label_from_value)
    })
    .or_else(|| {
        [
            "profile", "account", "member", "user", "actor", "subject", "details",
        ]
        .iter()
        .find_map(|key| {
            object
                .get(*key)
                .filter(|child| child.is_object())
                .and_then(|child| participant_handle_label_from_value(child, did))
        })
    })
}

fn participant_inline_handle_claim_label(
    claims: Option<&Value>,
    did: Option<&str>,
) -> Option<String> {
    let did = did?.trim();
    if did.is_empty() {
        return None;
    }
    claims?.as_array()?.iter().find_map(|claim| {
        let claim_subject = claim
            .get("subject")
            .or_else(|| claim.get("subject_id"))
            .and_then(Value::as_str)?;
        if claim_subject.trim() != did {
            return None;
        }
        let binding_state = claim
            .get("binding_state")
            .and_then(Value::as_str)
            .unwrap_or("verified");
        if !matches!(binding_state, "verified" | "active") {
            return None;
        }
        claim
            .get("handle")
            .and_then(Value::as_str)
            .and_then(mention_handle_label_from_value)
    })
}

pub(crate) fn mention_label_for_participant(participant: &SpaceParticipant) -> Option<String> {
    participant
        .handle_label
        .clone()
        .or_else(|| {
            participant
                .display_name
                .as_deref()
                .and_then(mention_handle_label_from_value)
        })
        .or_else(|| crate::views::helpers::handle_display_from_did(&participant.did))
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
        if role.rank() < existing.role.rank() {
            existing.role = role;
        }
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
) -> Vec<ParticipantRosterRow> {
    let visible_dids = participants
        .iter()
        .map(|participant| participant.did.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut agents_by_controller =
        std::collections::BTreeMap::<String, Vec<SpaceParticipant>>::new();
    for participant in participants
        .iter()
        .filter(|participant| participant.is_agent)
    {
        let Some(metadata) = participant.agent_metadata.as_ref() else {
            continue;
        };
        if metadata.controller_did.is_empty()
            || !visible_dids.contains(metadata.controller_did.as_str())
        {
            continue;
        }
        agents_by_controller
            .entry(metadata.controller_did.clone())
            .or_default()
            .push(participant.clone());
    }

    for agents in agents_by_controller.values_mut() {
        agents.sort_by(|left, right| {
            agent_display_label(left)
                .cmp(&agent_display_label(right))
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
    rows
}

pub(crate) fn collect_participant_field(
    value: &Value,
    key: &str,
    role: SpaceParticipantRole,
    account_did: &str,
    participants: &mut Vec<SpaceParticipant>,
) {
    let Some(field) = value.get(key) else {
        return;
    };

    if let Some(items) = field.as_array() {
        for item in items {
            let item_role = item
                .get("role")
                .and_then(Value::as_str)
                .map(|raw_role| participant_role_from_str(Some(raw_role), role))
                .unwrap_or(role);
            if let Some(did) = participant_id_from_value(item) {
                upsert_participant(
                    participants,
                    &did,
                    item_role,
                    account_did,
                    participant_display_name_from_value(item, Some(&did)),
                    participant_handle_label_from_value(item, Some(&did)),
                );
            }
        }
    } else if let Some(did) = participant_id_from_value(field) {
        upsert_participant(
            participants,
            &did,
            role,
            account_did,
            participant_display_name_from_value(field, Some(&did)),
            participant_handle_label_from_value(field, Some(&did)),
        );
    }
}

pub(crate) fn collect_state_participants(
    projection: &Value,
    account_did: &str,
    participants: &mut Vec<SpaceParticipant>,
) {
    let state_events = projection
        .get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            projection
                .get("state")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        );
    let state: Vec<&Value> = state_events.collect();
    if state.is_empty() {
        return;
    }

    for item in state {
        let kind = item
            .get("kind")
            .or_else(|| item.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let state_key = item
            .get("state_key")
            .or_else(|| item.get("key"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let body = item
            .get("content")
            .or_else(|| item.get("value"))
            .or_else(|| item.get("body"))
            .unwrap_or(item);

        let did = participant_id_from_state_key(state_key)
            .or_else(|| participant_id_from_member_value(body))
            .or_else(|| participant_id_from_member_value(item));
        if !kind.contains("member") && did.is_none() {
            continue;
        }

        let role = participant_role_from_str(
            body.get("role")
                .or_else(|| item.get("role"))
                .and_then(Value::as_str),
            SpaceParticipantRole::Member,
        );
        if let Some(did) = did {
            let display_name = participant_display_name_from_value(body, Some(&did))
                .or_else(|| participant_display_name_from_value(item, Some(&did)));
            let handle_label = participant_handle_label_from_value(body, Some(&did))
                .or_else(|| participant_handle_label_from_value(item, Some(&did)));
            upsert_participant(
                participants,
                &did,
                role,
                account_did,
                display_name,
                handle_label,
            );
        }
    }
}

pub(crate) fn space_participants(
    projection: Option<&Value>,
    account_did: &str,
) -> Vec<SpaceParticipant> {
    let mut participants = Vec::new();

    if let Some(projection) = projection {
        for key in ["owner", "created_by", "creator"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Owner,
                account_did,
                &mut participants,
            );
        }
        for key in ["owners", "admins", "admin_dids"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Admin,
                account_did,
                &mut participants,
            );
        }
        for key in ["members", "participants"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Member,
                account_did,
                &mut participants,
            );
        }

        if let Some(summary) = projection.get("summary") {
            for key in ["owner", "created_by", "creator"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Owner,
                    account_did,
                    &mut participants,
                );
            }
            for key in ["owners", "admins", "admin_dids"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Admin,
                    account_did,
                    &mut participants,
                );
            }
            for key in ["members", "participants"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Member,
                    account_did,
                    &mut participants,
                );
            }
        }

        collect_state_participants(projection, account_did, &mut participants);
    }

    if !account_did.trim().is_empty() {
        upsert_participant(
            &mut participants,
            account_did,
            SpaceParticipantRole::Member,
            account_did,
            None,
            None,
        );
    }

    participants.sort_by(|left, right| {
        right
            .is_self
            .cmp(&left.is_self)
            .then_with(|| left.role.rank().cmp(&right.role.rank()))
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
        .unwrap_or_else(|| crate::views::helpers::display_name_for_did(state_store, did))
}

pub(crate) fn is_own_message_sender(sender: &str, account_did: &str) -> bool {
    let sender = sender.trim();
    !sender.is_empty() && (sender == "yougen" || sender == account_did.trim())
}

pub(crate) fn short_principal_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "Unknown".to_owned();
    }
    let principal = trimmed.strip_prefix("did:web:").unwrap_or(trimmed);
    let tail = principal.rsplit(':').next().unwrap_or(principal);
    if tail.len() > 18 {
        format!("{}...{}", &tail[..8], &tail[tail.len() - 6..])
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

pub(crate) fn participant_sender_label(participant: &SpaceParticipant) -> Option<String> {
    if participant.is_agent {
        return Some(agent_display_label(participant));
    }
    participant_handle_label(participant).or_else(|| participant.display_name.clone())
}

pub(crate) fn participant_handle_label(participant: &SpaceParticipant) -> Option<String> {
    participant
        .handle_label
        .clone()
        .or_else(|| crate::views::helpers::handle_display_from_did(&participant.did))
}

fn display_name_is_handle_localpart(display_name: &str, handle_label: &str) -> bool {
    let Some(localpart) = handle_label.split(':').next() else {
        return false;
    };
    display_name.trim().eq_ignore_ascii_case(localpart.trim())
}

pub(crate) fn participant_roster_display_label(
    state_store: &LocalStateStore,
    participant: &SpaceParticipant,
) -> String {
    if participant.is_agent {
        return agent_display_label(participant);
    }
    participant_sender_label(participant).unwrap_or_else(|| {
        crate::views::helpers::display_name_for_did(state_store, &participant.did)
    })
}

pub(crate) fn agent_controller_label(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
) -> Option<String> {
    let metadata = participant.agent_metadata.as_ref()?;
    if !metadata.controller_handle.trim().is_empty() {
        return Some(metadata.controller_handle.clone());
    }
    participants
        .iter()
        .find(|candidate| candidate.did == metadata.controller_did)
        .and_then(participant_sender_label)
        .or_else(|| crate::views::helpers::handle_display_from_did(&metadata.controller_did))
        .or_else(|| {
            (!metadata.controller_did.trim().is_empty())
                .then(|| short_principal_label(&metadata.controller_did))
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
) -> Option<crate::messaging::mentions::MentionCandidate> {
    if participant.is_agent {
        let display_name = agent_display_label(participant);
        let selector = agent_selector_label(participant);
        let metadata = participant.agent_metadata.as_ref();
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
                .map(|metadata| metadata.controller_did.clone())
                .unwrap_or_default(),
            controller_handle_at_time: metadata
                .map(|metadata| metadata.controller_handle.clone())
                .unwrap_or_default(),
            agent_slug_at_time: metadata
                .map(|metadata| metadata.agent_slug.clone())
                .unwrap_or_default(),
        });
    }

    let handle_label = mention_label_for_participant(participant);
    let has_handle_label = handle_label.is_some();
    let display_name = handle_label
        .clone()
        .or_else(|| participant.display_name.clone())
        .unwrap_or_else(|| short_principal_label(&participant.did));
    Some(crate::messaging::mentions::MentionCandidate {
        did: participant.did.clone(),
        display_name,
        insert_label: handle_label.unwrap_or_else(|| short_principal_label(&participant.did)),
        subtitle: if has_handle_label {
            String::new()
        } else {
            "member DID".to_owned()
        },
        is_agent: false,
        controller_subject_id: String::new(),
        controller_handle_at_time: String::new(),
        agent_slug_at_time: String::new(),
    })
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
            .find(|participant| participant.did == account_did);
        let did_handle_label = crate::views::helpers::handle_display_from_did(account_did);
        let account_display_name =
            clean_participant_display_name(account_display_name, Some(account_did)).filter(
                |label| {
                    did_handle_label
                        .as_deref()
                        .is_none_or(|handle| !display_name_is_handle_localpart(label, handle))
                },
            );
        let participant_display_name = own_participant
            .and_then(|participant| participant.display_name.clone())
            .filter(|label| {
                did_handle_label
                    .as_deref()
                    .is_none_or(|handle| !display_name_is_handle_localpart(label, handle))
            });
        return own_participant
            .and_then(|participant| participant.handle_label.clone())
            .or(account_display_name)
            .or(participant_display_name)
            .or(did_handle_label)
            .unwrap_or_else(|| {
                if account_did.is_empty() {
                    "yougen".to_owned()
                } else {
                    short_principal_label(account_did)
                }
            });
    }
    participants
        .iter()
        .find(|participant| participant.did == sender.trim())
        .and_then(participant_sender_label)
        .or_else(|| crate::views::helpers::handle_display_from_did(sender))
        .unwrap_or_else(|| short_principal_label(sender))
}

/// CKP-0008 §4.10 — resolve the agent label for an act-on-behalf
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
