use super::*;

pub(crate) fn normalize_participant_id(value: &str) -> Option<arkret_sdk::DidCoreId> {
    arkret_sdk::DidCoreId::new(value.trim().to_owned()).ok()
}

#[cfg(test)]
#[test]
fn participant_membership_identity_and_self_badge_are_station_scoped() {
    let principal = "ak:did_core:web:chat-roster-isolation.example";
    let own = crate::mls_api_helpers::local_account_actor_id(principal).unwrap();
    let remote = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        own.signing_principal_id().clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap(),
    ));
    let projection = serde_json::json!({"member_roster_entries": [
        {"actor_id": own, "membership":"join"},
        {"actor_id": remote, "membership":"join", "subject_account_id": remote.as_account_id()}
    ]});
    let participants = space_participants(
        Some(&projection),
        &LocalStateStore::default(),
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        principal,
    );
    assert_eq!(participants.len(), 2);
    assert_eq!(
        participants
            .iter()
            .filter(|participant| participant.is_self)
            .count(),
        1
    );
    assert!(
        participants
            .iter()
            .find(|participant| participant.actor_id.as_ref() == Some(&own))
            .unwrap()
            .is_self
    );
    assert!(
        !participants
            .iter()
            .find(|participant| participant.actor_id.as_ref() == Some(&remote))
            .unwrap()
            .is_self
    );
    assert_ne!(participants[0].roster_key(), participants[1].roster_key());
}

#[cfg(test)]
#[test]
fn owned_agent_inventory_does_not_classify_another_stations_member() {
    let principal = "ak:did_core:web:agent-inventory-isolation.example";
    let remote = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new(principal).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap(),
    ));
    let mut participants = Vec::new();
    upsert_participant(
        &mut participants,
        &remote,
        SpaceParticipantRole::Member,
        "ak:did_core:web:controller.example",
        None,
        None,
    );
    let inventory = owned_agent_metadata(
        &std::collections::BTreeMap::from([(principal.to_owned(), "assistant".to_owned())]),
        "ak:did_core:web:controller.example",
        None,
    );
    annotate_agent_participants_with_metadata(&mut participants, &inventory);
    assert!(!participants[0].is_agent);
    assert!(participants[0].agent_metadata.is_none());
    assert_eq!(participants[0].actor_id, Some(remote));
}

#[cfg(test)]
#[test]
fn owned_agent_mention_uses_complete_joined_account_without_display_roster() {
    let controller = "ak:did_core:web:controller.example";
    let agent = "ak:did_core:web:joined-agent.example";
    let local = crate::mls_api_helpers::local_account_actor_id(agent).unwrap();
    let remote = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        local.signing_principal_id().clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap(),
    ));
    let unowned =
        crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:unowned-agent.example")
            .unwrap();
    let inventory = owned_agent_metadata(
        &std::collections::BTreeMap::from([(agent.to_owned(), "assistant".to_owned())]),
        controller,
        None,
    );
    let request =
        crate::views::chat::MentionInsertRequest::new(local.as_account_id().unwrap().clone(), true);
    let public = std::collections::BTreeSet::new();
    for joined in [
        None,
        Some(std::collections::BTreeSet::from([
            remote.clone(),
            unowned.clone(),
        ])),
    ] {
        let mut participants = Vec::new();
        upsert_joined_owned_agent_participants(
            &mut participants,
            joined.as_ref(),
            &inventory,
            controller,
        );
        upsert_agent_participants(&mut participants, &inventory, controller);
        annotate_agent_participants_with_metadata(&mut participants, &inventory);
        assert!(
            request
                .resolve_candidate(&participants, controller, &public)
                .is_none()
        );
    }
    let joined = std::collections::BTreeSet::from([local.clone(), remote.clone(), unowned]);
    let mut participants = Vec::new();
    upsert_joined_owned_agent_participants(
        &mut participants,
        Some(&joined),
        &inventory,
        controller,
    );
    upsert_agent_participants(&mut participants, &inventory, controller);
    annotate_agent_participants_with_metadata(&mut participants, &inventory);
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0].actor_id.as_ref(), Some(&local));
    let candidate = request
        .resolve_candidate(&participants, controller, &public)
        .expect("a joined owned Account can be selected without a display roster page");
    assert_eq!(
        candidate.subject_account_id,
        *local.as_account_id().unwrap()
    );
    assert!(
        request
            .resolve_candidate(&participants, "ak:did_core:web:other.example", &public)
            .is_none()
    );
    let remote_request = crate::views::chat::MentionInsertRequest::new(
        remote.as_account_id().unwrap().clone(),
        true,
    );
    assert!(
        remote_request
            .resolve_candidate(&participants, controller, &public)
            .is_none()
    );
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
    actor_id: &arkret_sdk::ActorId,
    role: SpaceParticipantRole,
    own_principal_id: &str,
    display_name: Option<(String, u8)>,
    handle_label: Option<String>,
) {
    let principal_id = actor_id.signing_principal_id().clone();
    let is_self = crate::mls_api_helpers::local_account_actor_id(own_principal_id)
        .is_ok_and(|own_actor| own_actor == *actor_id);
    if let Some(existing) = participants
        .iter_mut()
        .find(|candidate| candidate.actor_id.as_ref() == Some(actor_id))
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
            actor_id: Some(actor_id.clone()),
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
    let mut agents_by_controller =
        std::collections::BTreeMap::<String, Vec<SpaceParticipant>>::new();
    for participant in participants.iter().filter(|participant| {
        participant.is_agent && visible_agent_ids.contains(&participant.roster_key())
    }) {
        let Some(metadata) = participant.agent_metadata.as_ref() else {
            continue;
        };
        let controllers = participants
            .iter()
            .filter(|candidate| {
                same_principal_core(
                    candidate.principal_id.as_str(),
                    &metadata.controller_principal_id,
                )
            })
            .collect::<Vec<_>>();
        // Principal-only display metadata cannot choose between two Station accounts.
        let [controller] = controllers.as_slice() else {
            continue;
        };
        agents_by_controller
            .entry(controller.roster_key())
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
        .map(|agent| agent.roster_key())
        .collect::<std::collections::BTreeSet<_>>();

    let mut rows = Vec::new();
    for participant in participants {
        if participant.is_agent
            && !visible_agent_ids
                .iter()
                .any(|visible| same_principal_core(visible, participant.principal_id.as_str()))
        {
            continue;
        }
        if grouped_agent_ids.contains(&participant.roster_key()) {
            continue;
        }
        if let Some(agents) = agents_by_controller.get(&participant.roster_key())
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
    let Ok(actor) = serde_json::from_str::<arkret_sdk::ActorId>(agent_id) else {
        return false;
    };
    serde_json::from_str::<arkret_sdk::ActorId>(direct_peer_id).is_ok_and(|peer| peer == actor)
        || projected_member_ids.contains(&actor.to_string())
}

pub(crate) fn space_participants(
    projection: Option<&Value>,
    state_store: &LocalStateStore,
    realm_id: &str,
    principal_id: &str,
) -> Vec<SpaceParticipant> {
    let mut participants = Vec::new();

    let handle_issuer_policies =
        crate::views::member_display::realm_handle_issuer_policies(state_store, realm_id);
    for row in crate::views::member_display::realm_member_roster(projection) {
        let display = crate::views::member_display::resolve_member_display_with_policies(
            state_store,
            realm_id,
            &row,
            &handle_issuer_policies,
        );
        upsert_participant(
            &mut participants,
            &row.actor_id,
            SpaceParticipantRole::Member,
            principal_id,
            display.display_name.map(|name| (name, 1)),
            display.primary_handle,
        );
    }

    // Ordinary own-Station current carries verified MemberState rows. The
    // legacy display roster is optional enrichment, not the membership source.
    let joined = state_store
        .complete_joined_member_hint_for_realm(realm_id)
        .ok()
        .flatten();
    if let Some(joined) = joined.as_ref() {
        participants.retain(|participant| {
            participant
                .actor_id
                .as_ref()
                .is_some_and(|actor| joined.contains(actor))
        });
        for actor in joined {
            upsert_participant(
                &mut participants,
                &actor,
                SpaceParticipantRole::Member,
                principal_id,
                None,
                None,
            );
        }
    }

    if !principal_id.trim().is_empty()
        && let Ok(own_actor) = crate::mls_api_helpers::local_account_actor_id(principal_id)
        && joined
            .as_ref()
            .is_none_or(|members| members.contains(&own_actor))
    {
        let account_handle = state_store
            .primary_handle_for_principal_id(principal_id)
            .and_then(|handle| mention_handle_label_from_value(&handle));
        upsert_participant(
            &mut participants,
            &own_actor,
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
            .then_with(|| left.actor_id.cmp(&right.actor_id))
    });
    participants
}

pub(crate) fn presence_participant_ids(participants: &[SpaceParticipant]) -> Vec<String> {
    participants
        .iter()
        .filter_map(|participant| participant.actor_id.as_ref())
        .map(ToString::to_string)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
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
        .find(|participant| participant.roster_key() == actor_id)
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

/// §3.8.2 step 4c rendering of a principal with no resolvable name. One
/// shortener across the client: the chat surfaces used to carry their own,
/// which made the same unresolved account read differently per panel.
pub(crate) fn short_principal_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return crate::i18n::tr("identity.tier.unresolved");
    }
    crate::views::helpers::short_protocol_id(trimmed)
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
        .unwrap_or_else(|| short_principal_label(participant.principal_id.as_str()))
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
                && participant.agent_metadata.as_ref().is_some_and(|metadata| {
                    metadata.controller_principal_id.trim() == principal_id.trim()
                })
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
            participant.principal_id.as_str().trim() == principal_id.trim()
                || (participant.is_agent
                    && participant.agent_metadata.as_ref().is_some_and(|metadata| {
                        metadata.controller_principal_id.trim() == principal_id.trim()
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
        crate::views::helpers::actor_display_label(state_store, participant.principal_id.as_str())
    })
}

pub(crate) fn agent_controller_label(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
) -> Option<String> {
    let metadata = participant.agent_metadata.as_ref()?;
    participants
        .iter()
        .find(|candidate| candidate.principal_id.as_str() == metadata.controller_principal_id)
        .and_then(participant_sender_label)
        .or_else(|| {
            (!metadata.controller_handle.trim().is_empty())
                .then(|| metadata.controller_handle.clone())
        })
        .or_else(|| {
            (!metadata.controller_principal_id.trim().is_empty())
                .then(|| short_principal_label(&metadata.controller_principal_id))
        })
}

pub(crate) fn agent_selector_label(participant: &SpaceParticipant) -> Option<String> {
    // 0364 D2: historical/inventory metadata is not a current visible
    // selector claim. Until that proof is available, never advertise a
    // controller/slug label as a verified target.
    let _ = participant;
    None
}

/// Complete account a roster row can be mentioned at, or `None`.
///
/// A membership row already carries its exact `ActorId`; a `service` actor has
/// no account and can never be a mention subject. Inventory-only rows have no
/// complete AccountId and must not inherit this client's authoring Station.
pub(crate) fn participant_mention_account(
    participant: &SpaceParticipant,
) -> Option<arkret_sdk::AccountId> {
    participant.actor_id.as_ref()?.as_account_id().cloned()
}

pub(crate) fn mention_candidate_for_participant(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
    principal_id: &str,
) -> Option<crate::messaging::mentions::MentionCandidate> {
    let subject_account_id = participant_mention_account(participant)?;
    if participant.is_agent {
        // No verified current selector claim is available on this path.
        // The roster ActorId is complete, so the picker may still select the
        // exact account without disclosing or consuming a guessed slug.
        let (account_label, subtitle) = participant
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| (name.to_owned(), crate::i18n::tr("identity.tier.name_only")))
            .unwrap_or_else(|| {
                (
                    short_principal_label(subject_account_id.principal_id.as_str()),
                    crate::i18n::tr("identity.tier.unresolved"),
                )
            });
        let own_account = crate::mls_api_helpers::local_account_actor_id(principal_id)
            .ok()
            .and_then(|actor| actor.as_account_id().cloned());
        let is_owned_agent = participant.agent_metadata.as_ref().is_some_and(|metadata| {
            own_account.as_ref().is_some_and(|own| {
                same_principal_core(&metadata.controller_principal_id, own.principal_id.as_str())
                    && subject_account_id.station_id == own.station_id
            })
        });
        let labels = if is_owned_agent {
            // Private pickers contain only Agents. The active complete Account,
            // rather than a separately rendered controller row, owns `@me`.
            Some(arkret_sdk::AgentMentionLabels::new(
                "me",
                None,
                true,
                &account_label,
            ))
        } else {
            participant.agent_metadata.as_ref().and_then(|metadata| {
                let controller = participants.iter().find(|candidate| {
                    !candidate.is_agent
                        && candidate.principal_id.as_str() == metadata.controller_principal_id
                        && participant_mention_account(candidate).is_some_and(|account| {
                            account.station_id == subject_account_id.station_id
                        })
                })?;
                // Use public roster labels, never the Contact petname overlay.
                let public_holder = participant_handle_label(controller)
                    .unwrap_or_else(|| short_principal_label(controller.principal_id.as_str()));
                Some(arkret_sdk::AgentMentionLabels::new(
                    &public_holder,
                    None,
                    false,
                    &account_label,
                ))
            })
        };
        return Some(crate::messaging::mentions::MentionCandidate {
            subject_account_id,
            display_name: account_label.clone(),
            insert_label: labels.map(|labels| labels.shared).unwrap_or(account_label),
            subtitle,
            is_agent: true,
            is_owned_agent,
            controller_subject_account_id: None,
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        });
    }

    if participant.is_self {
        let display_name = participant_sender_label(participant)
            .unwrap_or_else(|| short_principal_label(participant.principal_id.as_str()));
        return Some(crate::messaging::mentions::MentionCandidate {
            subject_account_id,
            display_name,
            insert_label: "me".to_owned(),
            subtitle: "You".to_owned(),
            is_agent: false,
            is_owned_agent: false,
            controller_subject_account_id: None,
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        });
    }

    // An authorized roster's complete AccountId remains selectable even when
    // handle resolution is unavailable. Never turn the fallback into a handle
    // claim; mark its display as unresolved (identity-handles.md section 3.8).
    let (display_name, subtitle) = match mention_label_for_participant(participant) {
        Some(handle) => (handle, String::new()),
        None => (
            short_principal_label(participant.principal_id.as_str()),
            crate::i18n::tr("identity.tier.unresolved"),
        ),
    };
    Some(crate::messaging::mentions::MentionCandidate {
        subject_account_id,
        insert_label: display_name.clone(),
        display_name,
        subtitle,
        is_agent: false,
        is_owned_agent: false,
        controller_subject_account_id: None,
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
    _own_controller_handle: Option<&str>,
) -> Option<crate::messaging::mentions::MentionCandidate> {
    if requested_agent_slug.is_some() {
        return None;
    }
    if !agent_candidate_is_visible(participant, public_agent_ids, principal_id) {
        return None;
    }
    mention_candidate_for_participant(participant, participants, principal_id).or_else(|| {
        let subject_account_id = participant_mention_account(participant)?;
        let fallback_label = participant_sender_label(participant)
            .unwrap_or_else(|| short_principal_label(participant.principal_id.as_str()));
        Some(crate::messaging::mentions::MentionCandidate {
            subject_account_id,
            display_name: fallback_label.clone(),
            insert_label: fallback_label,
            subtitle: String::new(),
            is_agent: false,
            is_owned_agent: false,
            controller_subject_account_id: None,
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        })
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
    public_agent_ids.contains(&participant.roster_key())
        || participant
            .agent_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.controller_principal_id.trim() == principal_id.trim())
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
                .is_some_and(|metadata| metadata.controller_principal_id.trim() == principal_id)
        })
        .map(|participant| participant.principal_id.to_string())
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
        .find(|participant| participant.principal_id.as_str() == sender.trim())
        .and_then(participant_sender_label)
        .unwrap_or_else(|| crate::views::helpers::short_protocol_id(sender))
}

/// §4.10 — resolve the agent label for an act-on-behalf
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
        .find(|participant| participant.principal_id.as_str() == executed_by);
    match agent_participant {
        Some(participant) if participant.is_agent => Some(agent_display_label(participant)),
        // The executor is not a known agent participant — fall back to a
        // short principal label so the "via" attribution still renders.
        Some(_) => None,
        None => Some(short_principal_label(executed_by)),
    }
}
