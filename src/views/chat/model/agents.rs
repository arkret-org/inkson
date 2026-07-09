use super::*;

fn raw_operation_kind(payload: &Value) -> Option<&str> {
    payload
        .get("kind")
        .and_then(Value::as_str)
        .or_else(|| payload.get("type").and_then(Value::as_str))
}

/// Realm filter with fail-OPEN semantics: a record whose realm ownership is
/// unknown (no `realm_id` on the record or in the payload) still matches, so
/// local optimistic operations without a realm annotation stay visible.
/// Contrast with `members_panel::raw_operation_realm_matches_exact`, which
/// fail-closes on unknown ownership.
fn raw_operation_realm_matches_or_unscoped(
    record: &crate::local_state::RawOperationRecord,
    realm_id: &str,
) -> bool {
    let expected = realm_id.trim();
    if expected.is_empty() {
        return true;
    }
    record
        .realm_id
        .as_deref()
        .or_else(|| record.payload.get("realm_id").and_then(Value::as_str))
        .map(|record_realm| record_realm == expected)
        .unwrap_or(true)
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

fn string_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at_path(value, path).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn agent_endpoint_agent_id(payload: &Value) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "agent_id"],
            &["payload", "agent_id"],
            &["payload", "body", "agent_id"],
            &["agent_id"],
            &["target_ref"],
            &["unsigned", "local_target_ref"],
        ],
    )
}

fn agent_endpoint_controller_did(payload: &Value) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "controller_subject_id"],
            &["body", "controller_did"],
            &["payload", "controller_subject_id"],
            &["payload", "controller_did"],
            &["payload", "body", "controller_subject_id"],
            &["payload", "body", "controller_did"],
            &["controller_subject_id"],
            &["controller_did"],
            &["actor_id"],
            &["actor"],
        ],
    )
}

fn agent_endpoint_controller_handle(payload: &Value) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "controller_handle_at_time"],
            &["body", "controller_handle"],
            &["payload", "controller_handle_at_time"],
            &["payload", "controller_handle"],
            &["payload", "body", "controller_handle_at_time"],
            &["payload", "body", "controller_handle"],
            &["controller_handle_at_time"],
            &["controller_handle"],
        ],
    )
    .and_then(|handle| {
        crate::identity_handle::parse_user_handle(&handle).map(|parsed| parsed.handle)
    })
}

fn agent_endpoint_slug(payload: &Value) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "agent_slug"],
            &["payload", "agent_slug"],
            &["payload", "body", "agent_slug"],
            &["agent_slug"],
        ],
    )
    .filter(|slug| arkret_sdk::models::validate_agent_slug(slug).is_ok())
}

fn agent_endpoint_display_name(payload: &Value, agent_id: &str) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "display_name"],
            &["body", "agent_display_name"],
            &["payload", "display_name"],
            &["payload", "agent_display_name"],
            &["payload", "body", "display_name"],
            &["payload", "body", "agent_display_name"],
            &["display_name"],
            &["agent_display_name"],
        ],
    )
    .and_then(|value| clean_participant_display_name(&value, Some(agent_id)))
}

fn merge_agent_metadata(existing: &mut AgentParticipantMetadata, next: AgentParticipantMetadata) {
    if existing.controller_did.is_empty() {
        existing.controller_did = next.controller_did;
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

/// Scan local raw operations for `ck.agent.endpoint` rows and return
/// display metadata keyed by agent DID. The endpoint event only requires
/// `agent_id`; controller / slug / display fields are optional and are
/// consumed only when present. Missing controller falls back to the
/// endpoint event actor.
pub(crate) fn agent_metadata_from_raw_operations(
    raw_operations: &[crate::local_state::RawOperationRecord],
    realm_id: &str,
) -> std::collections::BTreeMap<String, AgentParticipantMetadata> {
    let mut out = std::collections::BTreeMap::new();
    for record in raw_operations {
        if raw_operation_kind(&record.payload) != Some("ak.agent.endpoint") {
            continue;
        }
        if !raw_operation_realm_matches_or_unscoped(record, realm_id) {
            continue;
        }
        let Some(agent_id) = agent_endpoint_agent_id(&record.payload) else {
            continue;
        };
        let next = AgentParticipantMetadata {
            controller_did: agent_endpoint_controller_did(&record.payload).unwrap_or_default(),
            controller_handle: agent_endpoint_controller_handle(&record.payload)
                .or_else(|| {
                    agent_endpoint_controller_did(&record.payload)
                        .and_then(|did| crate::views::helpers::handle_display_from_did(&did))
                })
                .unwrap_or_default(),
            agent_slug: agent_endpoint_slug(&record.payload).unwrap_or_default(),
            display_name: agent_endpoint_display_name(&record.payload, &agent_id)
                .unwrap_or_default(),
        };
        out.entry(agent_id)
            .and_modify(|existing| merge_agent_metadata(existing, next.clone()))
            .or_insert(next);
    }
    out
}

/// Compatibility helper for older call sites and tests that only need
/// the endpoint DID set.
#[cfg(test)]
pub(crate) fn agent_ids_from_raw_operations(
    raw_operations: &[crate::local_state::RawOperationRecord],
    realm_id: &str,
) -> Vec<String> {
    agent_metadata_from_raw_operations(raw_operations, realm_id)
        .into_keys()
        .collect()
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
            || arkret_sdk::models::validate_agent_slug(agent_slug).is_err()
        {
            continue;
        }
        let next = AgentParticipantMetadata {
            controller_did: controller_subject_id.as_str().trim().to_owned(),
            controller_handle: mention
                .controller_handle_at_time
                .as_ref()
                .and_then(|handle| crate::identity_handle::parse_user_handle(handle.canonical()))
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

pub(crate) fn merge_agent_metadata_maps(
    base: &mut std::collections::BTreeMap<String, AgentParticipantMetadata>,
    overlay: std::collections::BTreeMap<String, AgentParticipantMetadata>,
) {
    for (agent_id, metadata) in overlay {
        base.entry(agent_id)
            .and_modify(|existing| merge_agent_metadata(existing, metadata.clone()))
            .or_insert(metadata);
    }
}

/// Mark every participant whose DID appears in `agent_ids` as
/// `is_agent = true`. No-op for unknown DIDs.
#[cfg(test)]
pub(crate) fn annotate_agent_participants(
    participants: &mut [SpaceParticipant],
    agent_ids: &[String],
) {
    if agent_ids.is_empty() {
        return;
    }
    for participant in participants.iter_mut() {
        if agent_ids.iter().any(|did| did == &participant.did) {
            participant.is_agent = true;
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
