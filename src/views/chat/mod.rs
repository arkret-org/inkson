use arkret_sdk::push_rule_core::WatchLevel;
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::api_error::is_space_membership_denied_error;
use crate::circle::{CircleScope, CircleSummary};
use crate::components::{
    ActorIdentityLabel, CircleScopePicker, HelpTip, SecurityStateBadge, SelfAttributionBadge,
    UiIcon,
};
use crate::models::SubmitEventResult;
use crate::operation::{
    OperationBuilder, ak_ops, sdk_event_local_operation_id, trim_realm_id, uuid_v7,
};
use crate::payload::sdk_payload_value;
use crate::routes::Route;
use crate::state::{ClientLocalState, LocalStateStore};
use crate::transport::TransportClient;
use crate::transport::auth::{authed_api_with_sync, with_authed_api_with_sync};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{
    MentionNode, active_sync_token, parse_agent_selector_mention_tokens, parse_mention_nodes,
    short_protocol_id,
};
use crate::views::moderation_appeal::{AppealEntrypoint, AppealState};

mod composer;
mod controller;
mod effects;
mod model;
mod timeline;
mod timeline_surface;

const PRESENCE_HEARTBEAT_SECS: u64 = 25;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PendingSidecarMlsAdmission {
    sidecar_id: arkret_sdk::SidecarId,
    mls_group_id: arkret_sdk::MlsGroupId,
    desired_access_digest: arkret_sdk::Hash,
    commit: arkret_sdk::Event,
    welcomes: Vec<arkret_sdk::Event>,
    snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PendingSidecarMlsRemoval {
    sidecar_id: arkret_sdk::SidecarId,
    target_agent_id: arkret_sdk::Did,
    desired_access_digest: arkret_sdk::Hash,
    events: Vec<arkret_sdk::Event>,
    snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    idempotency_key: String,
}

fn pending_sidecar_mls_admission_key(sidecar_id: &arkret_sdk::SidecarId) -> String {
    format!("ak.local.sidecar_mls_admission.v1:{sidecar_id}")
}

fn pending_sidecar_mls_removal_key(sidecar_id: &arkret_sdk::SidecarId) -> String {
    format!("ak.local.sidecar_mls_removal.v1:{sidecar_id}")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MentionInsertRequest {
    request_id: String,
    target_id: String,
    agent_slug: Option<String>,
}

impl MentionInsertRequest {
    pub fn new(target_id: impl Into<String>, agent_slug: Option<String>) -> Self {
        Self {
            request_id: uuid_v7(),
            target_id: target_id.into(),
            agent_slug: agent_slug.filter(|slug| !slug.trim().is_empty()),
        }
    }
}

// Re-exported for the sync engine so the account-aggregate stream folds
// discussion message events into the shared `raw_operations` log (local-first
// feed), mirroring `kanban::kanban_operations_from_events`.
use composer::{ChatComposer, ChatComposerContext};
use controller::{
    ChatCommandContext, ChatController, ChatProjectionEvent, ChatProjectionSink,
    use_chat_controller,
};
use effects::ChatEffects;
pub(crate) use model::confirmed_sidecar_publish_message_operation;
#[cfg(test)]
pub(crate) use model::message_operations_from_events;
use model::*;
use timeline::*;
use timeline_surface::{ChatTimeline, ChatTimelineContext};

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
pub(crate) fn capture_chat_feed_scroll_position(realm_id: &str, strand_id: &str) {
    let key = serde_json::to_string(&format!("{realm_id}\u{1f}{strand_id}"))
        .expect("chat scroll key must serialize");
    let script = format!(
        r#"
window.__inksonChatFeedScrollOffsets ||= {{}};
const panels = document.querySelectorAll('[data-testid="chat-panel"]');
const panel = panels[panels.length - 1];
const feed = panel && panel.querySelector('[data-testid="message-list"]');
if (feed && feed.clientHeight > 0) {{
  const previous = window.__inksonChatFeedScrollOffsets[{key}];
  if (feed.scrollTop > 0 || !Number.isFinite(previous)) {{
    window.__inksonChatFeedScrollOffsets[{key}] = feed.scrollTop;
  }}
}}
"#
    );
    let _ = document::eval(&script);
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
pub(crate) fn restore_chat_feed_scroll_position(realm_id: &str, strand_id: &str) {
    let offset_key = format!("{realm_id}\u{1f}{strand_id}");
    let scroll_top = timeline_surface::chat_feed_scroll_offset(&offset_key);
    if scroll_top > 0.0 {
        timeline::scroll_chat_feed_to_offset(scroll_top);
    }
    let key = serde_json::to_string(&offset_key).expect("chat scroll key must serialize");
    let script = format!(
        r#"
setTimeout(() => {{
  const panels = document.querySelectorAll('[data-testid="chat-panel"]');
  const panel = panels[panels.length - 1];
  const feed = panel && panel.querySelector('[data-testid="message-list"]');
  const scrollTop = window.__inksonChatFeedScrollOffsets?.[{key}];
  if (feed && Number.isFinite(scrollTop)) {{
    feed.scrollTop = scrollTop;
  }}
}}, 0);
"#
    );
    let _ = document::eval(&script);
}

fn moderation_prompt_state(prompt: &ModerationAppealPrompt) -> AppealState {
    match prompt.state.as_str() {
        "submitted" => AppealState::Submitted,
        "under_review" => AppealState::UnderReview,
        "decided" => AppealState::Decided {
            verdict: prompt
                .verdict
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
        },
        "closed" => AppealState::Closed,
        _ => AppealState::None,
    }
}

fn timeline_projection_key(
    selected_realm_id: &str,
    realm_live_epoch: u64,
    visible_messages: &[ChatMessage],
    visible_moderation_appeal_prompts: &[ModerationAppealPrompt],
    private_sidecar_strand_ids: &std::collections::BTreeSet<String>,
) -> String {
    use std::hash::{Hash, Hasher};

    let mut projection = std::collections::hash_map::DefaultHasher::new();
    selected_realm_id.hash(&mut projection);
    realm_live_epoch.hash(&mut projection);
    for message in visible_messages {
        message.id.hash(&mut projection);
        message.protocol_message_id.hash(&mut projection);
        message.strand_id.hash(&mut projection);
        message.realm_id.hash(&mut projection);
        message.body.hash(&mut projection);
        message.timestamp.hash(&mut projection);
        message.reply_to.hash(&mut projection);
        message.reactions.hash(&mut projection);
        message.edited.hash(&mut projection);
        message.redacted.hash(&mut projection);
        message.pending.hash(&mut projection);
        message.failed.hash(&mut projection);
    }
    for prompt in visible_moderation_appeal_prompts {
        prompt.realm_id.hash(&mut projection);
        prompt.decision_ref.hash(&mut projection);
        prompt.target_ref.hash(&mut projection);
        prompt.state.hash(&mut projection);
        prompt.verdict.hash(&mut projection);
    }
    private_sidecar_strand_ids.hash(&mut projection);
    format!("{:016x}", projection.finish())
}

fn project_visible_messages(
    messages: &[ChatMessage],
    selected_channel_id: &str,
    selected_realm_id: &str,
    sidecar_projection: Option<(&str, &str, arkret_sdk::AgentSidecarDisplayMode)>,
    exchange_projections: &[arkret_sdk::AgentSidecarExchangeProjection],
) -> Vec<ChatMessage> {
    let mut visible = Vec::new();
    let mut positions = std::collections::BTreeMap::<String, usize>::new();
    let mut echo_projection_by_event = std::collections::BTreeMap::new();
    for projection in exchange_projections.iter().filter(|projection| {
        projection.source_track_ref.realm_id.as_str() == selected_realm_id
            && projection.source_track_ref.strand_id.as_str() == selected_channel_id
    }) {
        echo_projection_by_event
            .insert(projection.private_request_event_id.to_string(), projection);
        for event_id in &projection.user_facing_response_event_ids {
            echo_projection_by_event.insert(event_id.to_string(), projection);
        }
    }

    for message in messages {
        if !selected_realm_id.trim().is_empty() && message.realm_id != selected_realm_id {
            continue;
        }
        let is_source_echo = echo_projection_by_event.contains_key(&message.id);
        let strand_matches = sidecar_projection.map_or_else(
            || message.strand_id == selected_channel_id || is_source_echo,
            |(source_strand_id, private_strand_id, display_mode)| {
                message.strand_id == private_strand_id
                    || (display_mode == arkret_sdk::AgentSidecarDisplayMode::ContextMerged
                        && message.strand_id == source_strand_id)
            },
        );
        if !strand_matches {
            continue;
        }

        let Some((_, private_strand_id, _)) = sidecar_projection else {
            visible.push(message.clone());
            continue;
        };
        let dedupe_key = message.id.clone();
        if let Some(position) = positions.get(&dedupe_key).copied() {
            if message.strand_id == private_strand_id
                && visible[position].strand_id != private_strand_id
            {
                visible[position] = message.clone();
            }
        } else {
            positions.insert(dedupe_key, visible.len());
            visible.push(message.clone());
        }
    }
    let source_strand_id = sidecar_projection
        .map(|(source_strand_id, ..)| source_strand_id)
        .unwrap_or(selected_channel_id);
    let visible_source_ids = visible
        .iter()
        .filter(|message| message.strand_id == source_strand_id)
        .map(|message| message.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let wait_for_source_anchor = !sidecar_projection.is_some_and(|(_, _, display_mode)| {
        display_mode == arkret_sdk::AgentSidecarDisplayMode::SidecarOnly
    });
    if wait_for_source_anchor {
        visible.retain(|message| {
            echo_projection_by_event
                .get(&message.id)
                .is_none_or(|projection| {
                    projection
                        .source_frontier_anchor
                        .as_ref()
                        .is_none_or(|anchor| visible_source_ids.contains(anchor.as_str()))
                })
        });
    }
    let mut echoes = visible
        .iter()
        .filter_map(|message| {
            echo_projection_by_event
                .get(&message.id)
                .map(|projection| (message.id.clone(), (*projection).clone()))
        })
        .collect::<Vec<_>>();
    if !echoes.is_empty() {
        let echo_ids = echoes
            .iter()
            .map(|(event_id, _)| event_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let original = std::mem::take(&mut visible);
        let mut by_id = original
            .iter()
            .cloned()
            .map(|message| (message.id.clone(), message))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut ordered = original
            .into_iter()
            .filter(|message| !echo_ids.contains(message.id.as_str()))
            .collect::<Vec<_>>();
        echoes.sort_by(|left, right| {
            (
                left.1.source_hlc.to_string(),
                left.1.exchange_id.as_str(),
                left.0.as_str(),
            )
                .cmp(&(
                    right.1.source_hlc.to_string(),
                    right.1.exchange_id.as_str(),
                    right.0.as_str(),
                ))
        });
        for (event_id, projection) in echoes {
            let Some(message) = by_id.remove(&event_id) else {
                continue;
            };
            let mut insert_at = projection
                .source_frontier_anchor
                .as_ref()
                .and_then(|anchor| {
                    ordered
                        .iter()
                        .rposition(|candidate| candidate.id == anchor.as_str())
                        .map(|position| position + 1)
                })
                .unwrap_or(ordered.len());
            while projection.source_frontier_anchor.is_some()
                && insert_at < ordered.len()
                && echo_projection_by_event
                    .get(&ordered[insert_at].id)
                    .is_some_and(|existing| {
                        existing.source_frontier_anchor == projection.source_frontier_anchor
                    })
            {
                insert_at += 1;
            }
            ordered.insert(insert_at, message);
        }
        visible = ordered;
    }
    visible
}

async fn resolve_agent_selector_mentions(
    mentions_enabled: bool,
    base_url: &str,
    api_token: String,
    wait_for_sync_token: Option<String>,
    already_resolved: &[MentionNode],
    body: &str,
    realm_id: &str,
    requester: &str,
    own_controller_handle: Option<&str>,
) -> Vec<MentionNode> {
    if !mentions_enabled {
        return Vec::new();
    }
    let tokens = parse_agent_selector_mention_tokens(body);
    if tokens.is_empty() {
        return Vec::new();
    }
    let Ok(api) = authed_api_with_sync(base_url, api_token, wait_for_sync_token) else {
        return Vec::new();
    };
    let mut mentions = Vec::new();
    for token in tokens {
        if agent_selector_mention_is_already_resolved(already_resolved, &token, requester) {
            continue;
        }
        let controller_handle = if token.controller_handle == "me" {
            let Some(handle) = own_controller_handle
                .map(str::trim)
                .filter(|handle| !handle.is_empty())
            else {
                continue;
            };
            handle
        } else {
            token.controller_handle.as_str()
        };
        let Ok(outcome) = api
            .resolve_agent_selector_mention(
                controller_handle,
                &token.agent_slug,
                realm_id,
                requester,
            )
            .await
        else {
            continue;
        };
        let Ok(controller_handle) = arkret_sdk::Handle::parse(controller_handle) else {
            continue;
        };
        let mention = arkret_sdk::Mention::new(outcome.subject)
            .with_agent_selector_metadata(
                outcome.controller_subject,
                controller_handle,
                outcome.agent_slug,
            )
            .with_mention_text_original(token.mention_text_original)
            .with_resolved_at(chrono::Utc::now());
        mentions.push(MentionNode::mention(mention));
    }
    mentions
}

fn agent_selector_mention_is_already_resolved(
    mentions: &[MentionNode],
    token: &crate::views::helpers::AgentSelectorMentionToken,
    requester: &str,
) -> bool {
    mentions
        .iter()
        .filter_map(MentionNode::as_mention)
        .any(|mention| {
            if mention.agent_slug_at_time.as_deref() != Some(token.agent_slug.as_str()) {
                return false;
            }
            if token.controller_handle == "me" {
                return mention
                    .controller_subject_id
                    .as_ref()
                    .is_some_and(|controller| controller.as_str() == requester);
            }
            mention
                .controller_handle_at_time
                .as_ref()
                .is_some_and(|handle| handle.to_string() == token.controller_handle)
        })
}

fn owned_agent_ids_from_mentions(mentions: &[MentionNode], controller_id: &str) -> Vec<String> {
    let mut agent_ids = mentions
        .iter()
        .filter_map(MentionNode::as_mention)
        .filter(|mention| {
            mention
                .controller_subject_id
                .as_ref()
                .is_some_and(|controller| controller.as_str() == controller_id)
        })
        .map(|mention| mention.subject_id.as_str().to_owned())
        .collect::<Vec<_>>();
    agent_ids.sort_unstable();
    agent_ids.dedup();
    agent_ids
}

fn owned_agent_ids_from_composer(
    mentions_enabled: bool,
    body: &str,
    mentions: &[MentionNode],
    picker: &[crate::messaging::mentions::MentionCandidate],
    controller_id: &str,
) -> Vec<String> {
    if !mentions_enabled {
        return Vec::new();
    }
    let selector_slugs = parse_agent_selector_mention_tokens(body)
        .into_iter()
        .filter(|token| token.controller_handle == "me")
        .map(|token| token.agent_slug)
        .collect::<std::collections::BTreeSet<_>>();
    let mut agent_ids = owned_agent_ids_from_mentions(mentions, controller_id);
    agent_ids.extend(
        picker
            .iter()
            .filter(|candidate| candidate.is_agent)
            .filter(|candidate| candidate.controller_subject_id.trim() == controller_id.trim())
            .filter(|candidate| selector_slugs.contains(candidate.agent_slug_at_time.trim()))
            .filter_map(|candidate| {
                let did = candidate.did.trim();
                (!did.is_empty()).then(|| did.to_owned())
            }),
    );
    agent_ids.sort_unstable();
    agent_ids.dedup();
    agent_ids
}

fn should_route_owned_agent_to_sidecar(
    is_sidecar_composer: bool,
    selected_channel_is_circle_scoped: bool,
    has_owned_agent_ids: bool,
    has_self_agent_selector: bool,
) -> bool {
    !is_sidecar_composer
        && !selected_channel_is_circle_scoped
        && (has_owned_agent_ids || has_self_agent_selector)
}

#[derive(Clone, Debug)]
struct OwnedAgentSidecarEnsureResult {
    sidecar_id: arkret_sdk::SidecarId,
    private_strand_id: arkret_sdk::StrandId,
    private_relation_id: arkret_sdk::RelationId,
    view: arkret_sdk::AgentSidecarView,
}

fn sign_prepared_sidecar_event(
    draft: &arkret_sdk::protocol_journey::SidecarPreparedEventDraft,
    expected_kind: &str,
    controller_id: &arkret_sdk::Did,
    device_id: &str,
    source_realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<arkret_sdk::Event> {
    if draft.kind.as_str() != expected_kind {
        anyhow::bail!(
            "prepared Sidecar Event kind mismatch: expected {expected_kind}, got {}",
            draft.kind.as_str()
        );
    }
    let unsigned_bytes =
        arkret_sdk::base64url_decode(draft.unsigned_event_bytes.as_str().as_bytes())
            .map_err(|error| anyhow::anyhow!("invalid prepared Sidecar Event bytes: {error}"))?;
    let mut digest_payload: Value = serde_json::from_slice(&unsigned_bytes)
        .map_err(|error| anyhow::anyhow!("invalid prepared Sidecar Event payload: {error}"))?;
    let canonical_bytes = arkret_sdk::canonical::canonical_json_bytes(&digest_payload)?;
    if canonical_bytes != unsigned_bytes {
        anyhow::bail!("prepared Sidecar Event bytes are not canonical JSON");
    }
    let object = digest_payload
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("prepared Sidecar Event payload is not an object"))?;
    if object.contains_key("proofs")
        || object.contains_key("unsigned")
        || object.contains_key("actor_kind")
    {
        anyhow::bail!("prepared Sidecar Event payload contains a non-digest field");
    }
    object.insert("proofs".to_owned(), Value::Array(Vec::new()));
    let mut event: arkret_sdk::Event = serde_json::from_value(digest_payload)
        .map_err(|error| anyhow::anyhow!("invalid prepared Sidecar Event: {error}"))?;
    let digest = arkret_sdk::Hash::new(event.event_digest()?)?;
    if event.event_id != draft.event_id
        || event.kind != draft.kind
        || event.realm_id != *source_realm_id
        || event.actor_id != *controller_id
        || digest != draft.event_digest
        || !event.proofs.is_empty()
        || !event.unsigned.is_empty()
        || event.actor_kind.is_some()
    {
        anyhow::bail!("prepared Sidecar Event metadata does not match its canonical bytes");
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device signer is required for Sidecar commit"))?;
    let expected_verification_method =
        arkret_sdk::DidUrl::new(format!("{controller_id}#{device_id}"))
            .map_err(anyhow::Error::msg)?;
    if signer.device_id() != Some(device_id)
        || signer.verification_method_for_principal(controller_id)? != expected_verification_method
    {
        anyhow::bail!("active Sidecar signer is not bound to the authenticated controller device");
    }
    signer.sign_sdk_event_with_context(
        &mut event,
        crate::event_signer::EventProofContext::default(),
    )?;
    let signed_digest = arkret_sdk::Hash::new(event.event_digest()?)?;
    if signed_digest != draft.event_digest
        || event.proofs.is_empty()
        || event.proofs.iter().any(|proof| {
            proof.event_digest != draft.event_digest
                || proof.verification_method != expected_verification_method
        })
    {
        anyhow::bail!("signed Sidecar Event no longer matches its reservation draft");
    }
    Ok(event)
}

fn validate_prepared_sidecar_binding(
    create_event: Option<&arkret_sdk::Event>,
    context_attach_event: &arkret_sdk::Event,
    sidecar_id: &arkret_sdk::SidecarId,
    backing_circle_id: &arkret_sdk::CircleId,
    private_strand_id: &arkret_sdk::StrandId,
    private_relation_id: &arkret_sdk::RelationId,
    source_strand_id: &arkret_sdk::StrandId,
    controller_id: &arkret_sdk::Did,
    source_realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<()> {
    if let Some(create_event) = create_event {
        if !matches!(
            &create_event.scope_ref,
            arkret_sdk::ScopeRef::Realm { realm_id } if realm_id == source_realm_id
        ) {
            anyhow::bail!("Sidecar create draft has the wrong security scope");
        }
        let sidecar: arkret_sdk::AgentSidecar = serde_json::from_value(
            create_event
                .payload
                .get("object")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Sidecar create draft omitted object"))?,
        )?;
        sidecar.validate()?;
        if sidecar.id != *sidecar_id
            || sidecar.realm_id != *source_realm_id
            || sidecar.controller_id != *controller_id
            || sidecar.backing_circle_id != *backing_circle_id
            || sidecar.state != arkret_sdk::AgentSidecarState::Active
        {
            anyhow::bail!("Sidecar create draft object differs from its reservation");
        }
        if context_attach_event.refs.len() != 1
            || context_attach_event.refs[0].id != create_event.event_id.as_str()
            || context_attach_event.refs[0].role != "after"
            || !context_attach_event.refs[0].critical
            || context_attach_event.refs[0].proof.is_some()
        {
            anyhow::bail!(
                "Sidecar context attach draft does not exactly follow its reserved create Event"
            );
        }
    } else if !context_attach_event.refs.is_empty() {
        anyhow::bail!("existing Sidecar context attach draft has unexpected Event refs");
    }
    if !matches!(
        &context_attach_event.scope_ref,
        arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == source_realm_id && circle_id == backing_circle_id
    ) {
        anyhow::bail!("Sidecar context attach draft has the wrong security scope");
    }
    let private_strand = context_attach_event
        .payload
        .get("private_strand")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("Sidecar context attach omitted private_strand"))?;
    let relation = context_attach_event
        .payload
        .get("relation")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("Sidecar context attach omitted relation"))?;
    if context_attach_event
        .payload
        .get("sidecar_id")
        .and_then(Value::as_str)
        != Some(sidecar_id.as_str())
        || context_attach_event
            .payload
            .get("version")
            .and_then(Value::as_u64)
            != Some(1)
        || private_strand.get("id").and_then(Value::as_str) != Some(private_strand_id.as_str())
        || private_strand.get("realm_id").and_then(Value::as_str) != Some(source_realm_id.as_str())
        || private_strand
            .get("scope_circle_id")
            .and_then(Value::as_str)
            != Some(backing_circle_id.as_str())
        || private_strand.get("created_by").and_then(Value::as_str) != Some(controller_id.as_str())
        || relation.get("id").and_then(Value::as_str) != Some(private_relation_id.as_str())
        || relation.get("kind").and_then(Value::as_str) != Some("agent_sidecar_of")
        || relation.get("from_ref").and_then(Value::as_str) != Some(private_strand_id.as_str())
        || relation.get("to_ref").and_then(Value::as_str) != Some(source_strand_id.as_str())
        || relation.get("scope_circle_id").and_then(Value::as_str)
            != Some(backing_circle_id.as_str())
        || relation.get("created_by").and_then(Value::as_str) != Some(controller_id.as_str())
    {
        anyhow::bail!(
            "Sidecar context attach draft differs from its reservation or source context"
        );
    }
    Ok(())
}

fn accepted_sidecar_coordinates(
    outcome: &arkret_sdk::protocol_journey::SidecarEnsureOutcome,
    expected_operation_id: &arkret_sdk::protocol_journey::ProtocolOperationId,
    expected_phase: arkret_sdk::protocol_journey::SidecarAcceptedPhase,
) -> anyhow::Result<(
    arkret_sdk::SidecarId,
    arkret_sdk::StrandId,
    arkret_sdk::RelationId,
)> {
    outcome.validate()?;
    match outcome {
        arkret_sdk::protocol_journey::SidecarEnsureOutcome::Accepted {
            operation_id,
            accepted_phase,
            sidecar_id,
            private_strand_id,
            private_relation_id,
            access_readiness,
            ..
        } if operation_id == expected_operation_id && *accepted_phase == expected_phase => {
            if *access_readiness == arkret_sdk::protocol_journey::SidecarAccessReadiness::Failed {
                anyhow::bail!("Sidecar ceremony completed with failed access readiness");
            }
            Ok((
                sidecar_id.clone(),
                private_strand_id.clone(),
                private_relation_id.clone(),
            ))
        }
        arkret_sdk::protocol_journey::SidecarEnsureOutcome::Accepted { .. } => {
            anyhow::bail!("Sidecar accepted outcome changed its operation or phase binding")
        }
        arkret_sdk::protocol_journey::SidecarEnsureOutcome::Prepared { .. } => {
            anyhow::bail!("Sidecar commit returned another prepared outcome")
        }
    }
}

async fn ensure_owned_agent_sidecar(
    base_url: &str,
    api_token: String,
    trace_id: &str,
    controller_id: &str,
    device_id: &str,
    realm_id: &str,
    strand_id: &str,
    addressed_agent_ids: &[String],
    state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<Option<OwnedAgentSidecarEnsureResult>> {
    if addressed_agent_ids.is_empty() {
        return Ok(None);
    }
    let controller_id = arkret_sdk::Did::new(controller_id.to_owned())?;
    let source_realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let source_strand_id = arkret_sdk::StrandId::new(strand_id.to_owned())?;
    let mut addressed_agent_ids = addressed_agent_ids
        .iter()
        .cloned()
        .map(arkret_sdk::Did::new)
        .collect::<Result<Vec<_>, _>>()?;
    addressed_agent_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    addressed_agent_ids.dedup();
    if addressed_agent_ids
        .iter()
        .any(|agent_id| agent_id == &controller_id)
    {
        anyhow::bail!("Sidecar addressed Agents must exclude the controller");
    }
    let nonce = uuid_v7();
    let operation_id = arkret_sdk::protocol_journey::ProtocolOperationId::new(format!(
        "ak:operation:sidecar.ensure.{nonce}"
    ))
    .map_err(anyhow::Error::msg)?;
    let prepare_idempotency_key =
        arkret_sdk::protocol_journey::ProtocolOpaqueId::new(nonce).map_err(anyhow::Error::msg)?;
    let prepare = arkret_sdk::protocol_journey::SidecarEnsureRequestBody::Prepare(
        arkret_sdk::protocol_journey::SidecarEnsurePrepareRequestBody {
            phase: arkret_sdk::protocol_journey::SidecarPreparePhase::Prepare,
            operation_id: operation_id.clone(),
            idempotency_key: prepare_idempotency_key,
            source_realm_id: source_realm_id.clone(),
            controller_id: controller_id.clone(),
            context_ref: arkret_sdk::protocol_journey::SidecarContextRef::Strand {
                strand_id: source_strand_id.clone(),
            },
        },
    );
    tracing::info!(
        target: "sidecar",
        event = "sidecar.ensure.started",
        trace_id,
        operation_id = %operation_id,
        addressed_agent_count = addressed_agent_ids.len(),
    );
    let base_url_owned = base_url.to_owned();
    let ceremony_token = api_token.clone();
    let ceremony_operation_id = operation_id.clone();
    let ceremony_controller_id = controller_id.clone();
    let ceremony_realm_id = source_realm_id.clone();
    let ceremony_source_strand_id = source_strand_id.clone();
    let ceremony_device_id = device_id.to_owned();
    let (sidecar_id, backing_circle_id, private_strand_id, private_relation_id, mut view) =
        crate::transport::auth::with_authed_sdk_client(
            &base_url_owned,
            ceremony_token,
            move |http| async move {
                let prepared_or_accepted = http
                    .agent_sidecar_ensure(&prepare)
                    .await
                    .map_err(anyhow::Error::from)?;
                let (outcome, expected_phase, prepared_coordinates) = match prepared_or_accepted {
                    arkret_sdk::protocol_journey::SidecarEnsureOutcome::Accepted { .. } => {
                        anyhow::bail!(
                            "Sidecar prepare returned Accepted without a signed reservation ceremony"
                        )
                    }
                    arkret_sdk::protocol_journey::SidecarEnsureOutcome::Prepared { prepared } => {
                        let commit_idempotency_key =
                            arkret_sdk::protocol_journey::ProtocolOpaqueId::new(uuid_v7())
                                .map_err(anyhow::Error::msg)?;
                        match prepared {
                            arkret_sdk::protocol_journey::SidecarPreparedOutcome::New {
                                operation_id: prepared_operation_id,
                                reservation_handle,
                                expires_at,
                                sidecar_id,
                                backing_circle_id,
                                private_strand_id,
                                private_relation_id,
                                create_event_id,
                                context_attach_event_id,
                                create_event_draft,
                                context_attach_event_draft,
                                ..
                            } => {
                                if prepared_operation_id != ceremony_operation_id
                                    || expires_at <= crate::clock::now_utc()
                                    || create_event_id != create_event_draft.event_id
                                    || context_attach_event_id
                                        != context_attach_event_draft.event_id
                                {
                                    anyhow::bail!(
                                        "new Sidecar prepare returned inconsistent reservation bindings"
                                    );
                                }
                                let create_event = sign_prepared_sidecar_event(
                                    &create_event_draft,
                                    arkret_sdk::EventKind::SIDECAR_CREATE,
                                    &ceremony_controller_id,
                                    &ceremony_device_id,
                                    &ceremony_realm_id,
                                )?;
                                let context_attach_event = sign_prepared_sidecar_event(
                                    &context_attach_event_draft,
                                    arkret_sdk::EventKind::SIDECAR_CONTEXT_ATTACH,
                                    &ceremony_controller_id,
                                    &ceremony_device_id,
                                    &ceremony_realm_id,
                                )?;
                                validate_prepared_sidecar_binding(
                                    Some(&create_event),
                                    &context_attach_event,
                                    &sidecar_id,
                                    &backing_circle_id,
                                    &private_strand_id,
                                    &private_relation_id,
                                    &ceremony_source_strand_id,
                                    &ceremony_controller_id,
                                    &ceremony_realm_id,
                                )?;
                                let request = arkret_sdk::protocol_journey::SidecarEnsureRequestBody::Commit(
                                    arkret_sdk::protocol_journey::SidecarEnsureCommitRequestBody {
                                        phase: arkret_sdk::protocol_journey::SidecarCommitPhase::Commit,
                                        operation_id: ceremony_operation_id.clone(),
                                        idempotency_key: commit_idempotency_key,
                                        reservation_handle,
                                        create_event,
                                        context_attach_event,
                                    },
                                );
                                let outcome = http
                                    .agent_sidecar_ensure(&request)
                                    .await
                                    .map_err(anyhow::Error::from)?;
                                (
                                    outcome,
                                    arkret_sdk::protocol_journey::SidecarAcceptedPhase::Commit,
                                    Some((
                                        sidecar_id,
                                        backing_circle_id,
                                        private_strand_id,
                                        private_relation_id,
                                    )),
                                )
                            }
                            arkret_sdk::protocol_journey::SidecarPreparedOutcome::Existing {
                                operation_id: prepared_operation_id,
                                reservation_handle,
                                expires_at,
                                sidecar_id,
                                backing_circle_id,
                                private_strand_id,
                                private_relation_id,
                                context_attach_event_id,
                                context_attach_event_draft,
                                ..
                            } => {
                                if prepared_operation_id != ceremony_operation_id
                                    || expires_at <= crate::clock::now_utc()
                                    || context_attach_event_id
                                        != context_attach_event_draft.event_id
                                {
                                    anyhow::bail!(
                                        "existing Sidecar prepare returned inconsistent reservation bindings"
                                    );
                                }
                                let context_attach_event = sign_prepared_sidecar_event(
                                    &context_attach_event_draft,
                                    arkret_sdk::EventKind::SIDECAR_CONTEXT_ATTACH,
                                    &ceremony_controller_id,
                                    &ceremony_device_id,
                                    &ceremony_realm_id,
                                )?;
                                validate_prepared_sidecar_binding(
                                    None,
                                    &context_attach_event,
                                    &sidecar_id,
                                    &backing_circle_id,
                                    &private_strand_id,
                                    &private_relation_id,
                                    &ceremony_source_strand_id,
                                    &ceremony_controller_id,
                                    &ceremony_realm_id,
                                )?;
                                let request = arkret_sdk::protocol_journey::SidecarEnsureRequestBody::Attach(
                                    arkret_sdk::protocol_journey::SidecarEnsureAttachRequestBody {
                                        phase: arkret_sdk::protocol_journey::SidecarAttachPhase::Attach,
                                        operation_id: ceremony_operation_id.clone(),
                                        idempotency_key: commit_idempotency_key,
                                        reservation_handle,
                                        context_attach_event,
                                    },
                                );
                                let outcome = http
                                    .agent_sidecar_ensure(&request)
                                    .await
                                    .map_err(anyhow::Error::from)?;
                                (
                                    outcome,
                                    arkret_sdk::protocol_journey::SidecarAcceptedPhase::Attach,
                                    Some((
                                        sidecar_id,
                                        backing_circle_id,
                                        private_strand_id,
                                        private_relation_id,
                                    )),
                                )
                            }
                        }
                    }
                };
                let coordinates = accepted_sidecar_coordinates(
                    &outcome,
                    &ceremony_operation_id,
                    expected_phase,
                )?;
                if let Some((
                    prepared_sidecar_id,
                    _prepared_backing_circle_id,
                    prepared_private_strand_id,
                    prepared_private_relation_id,
                )) = &prepared_coordinates
                    && (prepared_sidecar_id != &coordinates.0
                        || prepared_private_strand_id != &coordinates.1
                        || prepared_private_relation_id != &coordinates.2)
                {
                    anyhow::bail!(
                        "Sidecar accepted coordinates differ from its signed reservation"
                    );
                }
                let prepared_backing_circle_id = prepared_coordinates
                    .as_ref()
                    .map(|prepared| prepared.1.clone())
                    .ok_or_else(|| anyhow::anyhow!("Sidecar ceremony omitted prepared coordinates"))?;
                let view = http
                    .agent_sidecar_get(&coordinates.0)
                    .await
                    .map_err(anyhow::Error::from)?;
                view.validate()?;
                if view.sidecar.id != coordinates.0
                    || view.sidecar.realm_id != ceremony_realm_id
                    || view.sidecar.controller_id != ceremony_controller_id
                    || prepared_coordinates.as_ref().is_some_and(|prepared| {
                        view.sidecar.backing_circle_id != prepared.1
                    })
                {
                    anyhow::bail!("Sidecar View does not match the accepted ceremony binding");
                }
                Ok::<_, anyhow::Error>((
                    coordinates.0,
                    prepared_backing_circle_id,
                    coordinates.1,
                    coordinates.2,
                    view,
                ))
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
    if addressed_agent_ids
        .iter()
        .any(|agent_id| !view.desired_agent_ids.contains(agent_id))
    {
        anyhow::bail!("an addressed Agent is absent from the accepted Sidecar desired access");
    }
    view = ensure_sidecar_mls_bootstrap(
        base_url,
        api_token.clone(),
        controller_id.as_str(),
        device_id,
        state_store,
        view,
    )
    .await?;
    view = reconcile_sidecar_mls_access(
        base_url,
        api_token,
        controller_id.as_str(),
        device_id,
        state_store,
        view,
    )
    .await?;
    view.validate()?;
    if view.sidecar.id != sidecar_id
        || view.sidecar.realm_id != source_realm_id
        || view.sidecar.controller_id != controller_id
        || view.sidecar.backing_circle_id != backing_circle_id
        || addressed_agent_ids
            .iter()
            .any(|agent_id| !view.desired_agent_ids.contains(agent_id))
    {
        anyhow::bail!("reconciled Sidecar View changed its ceremony or desired-access binding");
    }
    tracing::info!(
        target: "sidecar",
        event = "sidecar.ensure.completed",
        trace_id,
        operation_id = %operation_id,
        sidecar_id = %sidecar_id,
        access_readiness = ?view.access_readiness,
    );
    Ok(Some(OwnedAgentSidecarEnsureResult {
        sidecar_id,
        private_strand_id,
        private_relation_id,
        view,
    }))
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
async fn reconcile_sidecar_mls_access(
    base_url: &str,
    api_token: String,
    controller_id: &str,
    device_id: &str,
    mut state_store: SyncSignal<LocalStateStore>,
    mut view: arkret_sdk::AgentSidecarView,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    if view.mls_context.current_controller_device_ready {
        view = reconcile_sidecar_mls_removals(
            base_url,
            api_token.clone(),
            controller_id,
            device_id,
            state_store,
            view,
        )
        .await?;
    }
    let Some(group_id) = view.mls_context.mls_group_id.as_ref() else {
        return Ok(view);
    };
    let missing = view
        .pending_access_reconciliations
        .iter()
        .filter(|pending| {
            pending.provisioning_phase
                == arkret_sdk::PendingSidecarAccessReconciliationStage::MlsWelcome
                && matches!(
                    pending.reason.as_str(),
                    "mls_welcome_or_epoch_commit_pending" | "mls_group_or_welcome_pending"
                )
        })
        .map(|pending| pending.agent_id.clone())
        .collect::<Vec<_>>();
    let pending_key = pending_sidecar_mls_admission_key(&view.sidecar.id);
    if missing.is_empty() {
        if view.pending_access_reconciliations.iter().any(|pending| {
            pending.provisioning_phase
                == arkret_sdk::PendingSidecarAccessReconciliationStage::DeviceKeyMaterial
        }) {
            state_store.write().remove_private_data(&pending_key);
        }
        return Ok(view);
    }
    if !view.mls_context.current_controller_device_ready {
        return Ok(view);
    }
    let realm_id = view.sidecar.realm_id.to_string();
    let circle_id = view.sidecar.backing_circle_id.to_string();
    let sidecar_id = view.sidecar.id.clone();
    let sidecar_binding = sidecar_mls_binding(&view);
    let group_id = group_id.to_string();
    let controller_id = controller_id.to_owned();
    let device_id = device_id.to_owned();
    crate::transport::auth::with_authed_api(base_url, api_token, move |api| async move {
        let mut pending = state_store
            .read()
            .load_private_data(&controller_id, &pending_key)
            .map(|raw| serde_json::from_str::<PendingSidecarMlsAdmission>(&raw))
            .transpose()?;
        if pending.as_ref().is_some_and(|pending| {
            pending.sidecar_id != sidecar_id
                || pending.mls_group_id.as_str() != group_id
                || pending.desired_access_digest != sidecar_binding.desired_access_digest
        }) {
            state_store.write().remove_private_data(&pending_key);
            pending = None;
        }
        if pending.is_none() {
            let snapshot = state_store
                .read()
                .mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id))
                .ok_or_else(|| anyhow::anyhow!("Sidecar MLS controller snapshot is unavailable"))?;
            if snapshot.group_id != group_id {
                anyhow::bail!("Sidecar MLS controller snapshot is not the accepted group");
            }
            let proof_request = crate::mls::governance_proof::proof_request(
                &state_store.read(),
                &realm_id,
                Some(&circle_id),
                group_id.clone(),
                snapshot.epoch,
                snapshot.epoch.saturating_add(1),
            )
            .map_err(anyhow::Error::msg)?;
            let mut claims = Vec::new();
            for agent_id in missing {
                let claim_nonce = crate::mls_api_helpers::generate_mls_claim_nonce()?;
                let endpoints =
                    crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
                let outcome = endpoints
                    .mls()
                    .claim_key_package(
                        agent_id.as_str(),
                        &realm_id,
                        &controller_id,
                        &claim_nonce,
                        None,
                        Some(&group_id),
                    )
                    .await?;
                if let Some(claim) = outcome.claims.into_iter().next() {
                    claims.push((claim, claim_nonce));
                }
            }
            if claims.is_empty() {
                return api
                    .sdk_http_client()?
                    .agent_sidecar_get(&sidecar_id)
                    .await
                    .map_err(anyhow::Error::from);
            }
            let current_leaves = crate::mls::governance_proof::current_security_frontier_leaves(
                &state_store.read(),
                &realm_id,
                Some(&circle_id),
                &controller_id,
                &device_id,
            )
            .map_err(anyhow::Error::msg)?;
            let added_claims = claims.iter().map(|(claim, _)| claim).collect::<Vec<_>>();
            let proof_leaves = crate::mls::governance_proof::security_frontier_with_added_claims(
                current_leaves,
                &added_claims,
            )
            .map_err(anyhow::Error::msg)?;
            crate::mls::governance_proof::fetch_verify_and_cache_proof_bundle(
                &api,
                state_store,
                &proof_request,
                &proof_leaves,
            )
            .await
            .map_err(anyhow::Error::msg)?;
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let admission = crate::mls::admission::build_sidecar_mls_admission_events_from_claims(
                &state_store.read(),
                secure_store.as_ref(),
                &realm_id,
                &circle_id,
                &controller_id,
                &device_id,
                &claims,
                sidecar_binding.clone(),
            )
            .map_err(anyhow::Error::msg)?;
            let submitter = api.event_submitter()?;
            let commit = submitter
                .prepare_sdk_events_batch(vec![admission.commit])
                .await?
                .into_iter()
                .next()
                .expect("single Sidecar Commit preparation preserves cardinality");
            let prepared = PendingSidecarMlsAdmission {
                sidecar_id: sidecar_id.clone(),
                mls_group_id: arkret_sdk::MlsGroupId::new(group_id.clone())
                    .map_err(anyhow::Error::msg)?,
                desired_access_digest: sidecar_binding.desired_access_digest,
                commit,
                welcomes: admission.welcomes,
                snapshot: admission.snapshot,
            };
            state_store.write().save_private_data(
                &controller_id,
                pending_key.clone(),
                serde_json::to_string(&prepared)?,
            );
            pending = Some(prepared);
        }
        let mut pending = pending.expect("pending Sidecar MLS admission initialized");
        let submitter = api.event_submitter()?;
        submitter.submit_signed_sdk_event(&pending.commit).await?;
        state_store
            .write()
            .record_mls_group_state_ref_for_effective_scope(
                realm_id.clone(),
                Some(&circle_id),
                pending.snapshot.group_id.as_str(),
                pending.snapshot.epoch,
                pending.commit.event_id.clone(),
            )
            .map_err(anyhow::Error::msg)?;
        state_store.write().save_mls_snapshot_for_effective_scope(
            realm_id.clone(),
            Some(&circle_id),
            pending.snapshot.clone(),
        );
        if pending
            .welcomes
            .iter()
            .any(|welcome| welcome.proofs.is_empty())
        {
            pending.welcomes = submitter.prepare_sdk_events_batch(pending.welcomes).await?;
            state_store.write().save_private_data(
                &controller_id,
                pending_key.clone(),
                serde_json::to_string(&pending)?,
            );
        }
        for welcome in &pending.welcomes {
            submitter.submit_signed_sdk_event(welcome).await?;
        }
        state_store.write().remove_private_data(&pending_key);
        api.sdk_http_client()?
            .agent_sidecar_get(&sidecar_id)
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))
}

async fn reconcile_sidecar_mls_removals(
    base_url: &str,
    api_token: String,
    controller_id: &str,
    device_id: &str,
    mut state_store: SyncSignal<LocalStateStore>,
    view: arkret_sdk::AgentSidecarView,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    let sidecar_id = view.sidecar.id.clone();
    let realm_id = view.sidecar.realm_id.to_string();
    let circle_id = view.sidecar.backing_circle_id.to_string();
    let pending_key = pending_sidecar_mls_removal_key(&sidecar_id);
    let removals = view
        .pending_access_reconciliations
        .iter()
        .filter(|pending| {
            pending.provisioning_phase
                == arkret_sdk::PendingSidecarAccessReconciliationStage::MlsRemove
        })
        .cloned()
        .collect::<Vec<_>>();
    let has_persisted = state_store
        .read()
        .load_private_data(controller_id, &pending_key)
        .is_some();
    if removals.is_empty() && !has_persisted {
        return Ok(view);
    }
    let controller_id = controller_id.to_owned();
    let device_id = device_id.to_owned();
    let sidecar_binding = sidecar_mls_binding(&view);
    crate::transport::auth::with_authed_api(base_url, api_token, move |api| async move {
        let persisted = {
            state_store
                .read()
                .load_private_data(&controller_id, &pending_key)
        };
        if let Some(raw) = persisted {
            let pending = serde_json::from_str::<PendingSidecarMlsRemoval>(&raw)?;
            let body = arkret_sdk::CircleScopeRotateRequestBody {
                events: pending.events.clone(),
                idempotency_key: Some(pending.idempotency_key.clone()),
            };
            api.sdk_http_client()?
                .circle_scope_rotate(&circle_id, &pending.idempotency_key, &body)
                .await
                .map_err(anyhow::Error::from)?;
            let commit_event_id = pending
                .events
                .iter()
                .find(|event| event.kind.as_str() == "ak.mls.commit")
                .map(|event| event.event_id.clone())
                .ok_or_else(|| anyhow::anyhow!("Sidecar removal has no MLS commit Event"))?;
            state_store
                .write()
                .record_mls_group_state_ref_for_effective_scope(
                    realm_id.clone(),
                    Some(&circle_id),
                    pending.snapshot.group_id.as_str(),
                    pending.snapshot.epoch,
                    commit_event_id,
                )
                .map_err(anyhow::Error::msg)?;
            state_store.write().save_mls_snapshot_for_effective_scope(
                realm_id.clone(),
                Some(&circle_id),
                pending.snapshot,
            );
            state_store.write().remove_private_data(&pending_key);
            return api
                .sdk_http_client()?
                .agent_sidecar_get(&sidecar_id)
                .await
                .map_err(anyhow::Error::from);
        }
        for removal in removals {
            let membership_frontier = removal.membership_frontier.as_deref().ok_or_else(|| {
                anyhow::anyhow!("Sidecar MLS removal is missing its membership frontier")
            })?;
            let snapshot = state_store
                .read()
                .mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id))
                .ok_or_else(|| anyhow::anyhow!("Sidecar MLS controller snapshot is unavailable"))?;
            let proof_request = crate::mls::governance_proof::proof_request(
                &state_store.read(),
                &realm_id,
                Some(&circle_id),
                snapshot.group_id.clone(),
                snapshot.epoch,
                snapshot.epoch.saturating_add(1),
            )
            .map_err(anyhow::Error::msg)?;
            let current_leaves = crate::mls::governance_proof::current_security_frontier_leaves(
                &state_store.read(),
                &realm_id,
                Some(&circle_id),
                &controller_id,
                &device_id,
            )
            .map_err(anyhow::Error::msg)?;
            let proof_leaves = crate::mls::governance_proof::security_frontier_without_principals(
                current_leaves,
                &[removal.agent_id.to_string()],
            );
            crate::mls::governance_proof::fetch_verify_and_cache_proof_bundle(
                &api,
                state_store,
                &proof_request,
                &proof_leaves,
            )
            .await
            .map_err(anyhow::Error::msg)?;
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let draft = crate::circle_mls::build_sidecar_remove_scope_rotate_draft(
                &state_store.read(),
                secure_store.as_ref(),
                &realm_id,
                &circle_id,
                &controller_id,
                &device_id,
                removal.agent_id.as_str(),
                membership_frontier,
                sidecar_binding.clone(),
            )
            .map_err(anyhow::Error::msg)?;
            let events = api
                .event_submitter()?
                .prepare_sdk_events_batch(draft.events)
                .await?;
            let pending = PendingSidecarMlsRemoval {
                sidecar_id: sidecar_id.clone(),
                target_agent_id: removal.agent_id,
                desired_access_digest: sidecar_binding.desired_access_digest.clone(),
                events,
                snapshot: draft.post_commit_snapshot,
                idempotency_key: uuid_v7(),
            };
            state_store.write().save_private_data(
                &controller_id,
                pending_key.clone(),
                serde_json::to_string(&pending)?,
            );
            let body = arkret_sdk::CircleScopeRotateRequestBody {
                events: pending.events.clone(),
                idempotency_key: Some(pending.idempotency_key.clone()),
            };
            api.sdk_http_client()?
                .circle_scope_rotate(&circle_id, &pending.idempotency_key, &body)
                .await
                .map_err(anyhow::Error::from)?;
            let commit_event_id = pending
                .events
                .iter()
                .find(|event| event.kind.as_str() == "ak.mls.commit")
                .map(|event| event.event_id.clone())
                .ok_or_else(|| anyhow::anyhow!("Sidecar removal has no MLS commit Event"))?;
            state_store
                .write()
                .record_mls_group_state_ref_for_effective_scope(
                    realm_id.clone(),
                    Some(&circle_id),
                    pending.snapshot.group_id.as_str(),
                    pending.snapshot.epoch,
                    commit_event_id,
                )
                .map_err(anyhow::Error::msg)?;
            state_store.write().save_mls_snapshot_for_effective_scope(
                realm_id.clone(),
                Some(&circle_id),
                pending.snapshot,
            );
            state_store.write().remove_private_data(&pending_key);
        }
        api.sdk_http_client()?
            .agent_sidecar_get(&sidecar_id)
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))
}

fn sidecar_mls_binding(view: &arkret_sdk::AgentSidecarView) -> arkret_sdk::SidecarMlsBinding {
    arkret_sdk::SidecarMlsBinding {
        sidecar_id: view.sidecar.id.clone(),
        desired_access_digest: view.mls_context.desired_access_digest.clone(),
        control_frontier: view.mls_context.control_frontier.clone(),
    }
}

struct SourceRoutedSidecarMessageOutcome {
    event_id: String,
}

#[allow(clippy::too_many_arguments)]
async fn submit_source_routed_sidecar_message(
    base_url: &str,
    api_token: String,
    controller_id: &str,
    device_id: &str,
    source_realm_id: &str,
    source_strand_id: &str,
    private_strand_id: &str,
    source_frontier_anchor: Option<&str>,
    body: &str,
    mentions: &[MentionNode],
    addressed_agent_ids: &[String],
    mut state_store: SyncSignal<LocalStateStore>,
    view: &arkret_sdk::AgentSidecarView,
) -> anyhow::Result<SourceRoutedSidecarMessageOutcome> {
    view.validate()?;
    if view.access_readiness != arkret_sdk::AgentSidecarAccessReadiness::Ready
        || !view.mls_context.current_controller_device_ready
    {
        anyhow::bail!("Sidecar MLS access is not ready for a private routed write");
    }
    let mut addressed = addressed_agent_ids
        .iter()
        .map(|agent_id| arkret_sdk::Did::new(agent_id.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    addressed.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    addressed.dedup();
    if addressed.is_empty()
        || addressed
            .iter()
            .any(|agent_id| !view.effective_agent_ids.contains(agent_id))
    {
        anyhow::bail!("Every addressed Agent must have effective Sidecar MLS access");
    }
    let mut content = chat_content_block_for_body(body)?;
    let actor_mentions = mentions
        .iter()
        .filter_map(|mention| mention.as_mention().cloned())
        .collect::<Vec<_>>();
    if !actor_mentions.is_empty() {
        content = content.with_mentions(actor_mentions)?;
    }
    let audience_mentions = mentions
        .iter()
        .filter_map(|mention| mention.as_audience_mention().cloned())
        .collect::<Vec<_>>();
    if !audience_mentions.is_empty() {
        content = content.with_audience_mentions(audience_mentions)?;
    }
    let content_value =
        sdk_payload_value(content.to_value(), "Sidecar routed content block serialize")?;
    let content_bytes = serde_json::to_vec(&content_value)?;
    let message_id = new_chat_message_id();
    let circle_id = view.sidecar.backing_circle_id.to_string();
    // Client-local pending intent (§7.2.4): a rejected submit leaves NO
    // durable exchange state, and retrying the same composer intent MUST
    // reuse the same `exchange_id`, so the exchange identity lives in a
    // pending record keyed by the intent digest until the server accepts.
    let addressed_strings = addressed
        .iter()
        .map(|agent_id| agent_id.as_str().to_owned())
        .collect::<Vec<_>>();
    let intent_digest = crate::sidecar::sidecar_submission_intent_digest(
        source_strand_id,
        body,
        &addressed_strings,
    );
    // F-7 equivocation guard: one in-flight submit per intent. A concurrent
    // double-click would otherwise author two request Events under the SAME
    // exchange_id (the pending record is read before either submit lands).
    let Some(_submission_guard) = crate::sidecar::try_begin_sidecar_submission(
        controller_id,
        private_strand_id,
        &intent_digest,
    ) else {
        anyhow::bail!("This Private Sidecar request is already being submitted");
    };
    let prior_intent = crate::sidecar::load_pending_sidecar_submission(
        &state_store.read(),
        controller_id,
        private_strand_id,
        &intent_digest,
    );
    let request_context = match &prior_intent {
        // Retry of the same intent: reuse the full stored request context so
        // exchange identity and ordering keys stay stable across attempts.
        Some(pending) => pending.request_context.clone(),
        None => arkret_sdk::AgentSidecarExchangeRequestContext {
            source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
                realm_id: arkret_sdk::RealmId::new(source_realm_id.to_owned())?,
                strand_id: arkret_sdk::StrandId::new(source_strand_id.to_owned())?,
                track_name: "discussion".to_owned(),
            },
            source_hlc: crate::signing_stamp::issue_protocol_hlc(
                controller_id,
                device_id,
                source_realm_id,
            )?,
            client_order_key: arkret_sdk::NonEmptyString::new(uuid_v7())
                .map_err(anyhow::Error::msg)?,
            addressed_agent_ids: addressed.clone(),
            completion_policy: arkret_sdk::AgentSidecarExchangeCompletionPolicy::Coordinator,
            // §7.2.1: with a single addressed Agent the coordinator MAY be
            // omitted (implied). With several, the field is REQUIRED; the UI
            // has no dedicated coordinator picker yet, so the first entry of
            // the (sorted, deduped) addressed set is used deterministically.
            coordinator_agent_id: (addressed.len() > 1).then(|| addressed[0].clone()),
            source_frontier_anchor: source_frontier_anchor
                .filter(|anchor| !anchor.trim().is_empty())
                .and_then(|anchor| arkret_sdk::EventId::new(anchor.to_owned()).ok()),
        },
    };
    let exchange_id = match &prior_intent {
        Some(pending) => pending.exchange_id.clone(),
        None => arkret_sdk::AgentSidecarExchangeId::new(uuid_v7())?,
    };
    // Typed producer binding. It travels ONLY in the encrypted_metadata
    // plaintext (`message_metadata.sidecar_exchange_binding`); plaintext
    // `metadata` and the content block never carry it (§7.2.1).
    let binding = arkret_sdk::AgentSidecarEventExchangeBinding::request(
        exchange_id.clone(),
        request_context.clone(),
    )?;
    let mut message_metadata = arkret_sdk::MessageMetadata::default();
    message_metadata.set_sidecar_exchange_binding(&binding)?;
    let metadata_bytes = serde_json::to_vec(&message_metadata)?;
    let seal_view = state_store.read().seal_view_for_realm(source_realm_id);
    let build = crate::views::secure_send::build_secure_send(
        state_store,
        &seal_view,
        source_realm_id,
        controller_id,
        device_id,
        private_strand_id,
        &message_id,
        None,
        &content_bytes,
        Some(&metadata_bytes),
        None,
        Some(&circle_id),
        Some(sidecar_mls_binding(view)),
    )
    .map_err(anyhow::Error::msg)?;
    let local_operation_id = sdk_event_local_operation_id(&build.message_event).to_owned();
    let pending = crate::sidecar::PendingSidecarSubmission {
        controller_id: controller_id.to_owned(),
        sidecar_id: view.sidecar.id.clone(),
        private_strand_id: private_strand_id.to_owned(),
        backing_circle_id: view.sidecar.backing_circle_id.clone(),
        exchange_id,
        request_context,
        message_id: message_id.clone(),
        local_operation_id: local_operation_id.clone(),
    };
    crate::sidecar::save_pending_sidecar_submission(
        &mut state_store.write(),
        &intent_digest,
        &pending,
    )?;
    let api = crate::transport::auth::authed_api_with_sync(base_url, api_token.clone(), None)?;
    let outcome = crate::views::secure_send::submit_secure_send(
        &api,
        state_store,
        build,
        source_realm_id,
        device_id,
        base_url.to_owned(),
        api_token.clone(),
        controller_id.to_owned(),
        Some(circle_id),
    )
    .await;
    let (event_id, status) = match outcome {
        crate::views::secure_send::SecureSendOutcome::Sent { event_id, status } => {
            (event_id, status)
        }
        // Rejected/failed submit: the pending intent record stays (retryable)
        // and no durable exchange state is produced (§7.2.4).
        crate::views::secure_send::SecureSendOutcome::CommitFailed { message }
        | crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
            anyhow::bail!(message)
        }
    };
    {
        let mut store = state_store.write();
        store.append_raw_operation(
            local_operation_id,
            Some(source_realm_id.to_owned()),
            json!({
                "event_id": event_id.clone(),
                "kind": "ak.message.create",
                "actor_id": controller_id,
                "strand_id": private_strand_id,
                "message_id": message_id.clone(),
                "encrypted_content": true,
                "status": status,
            }),
        );
        store.save_private_plaintext(
            source_realm_id,
            private_strand_id,
            &format!("message:{message_id}"),
            body,
        );
        // Accepted: drop the client-local pending intent and fold the
        // accepted request into the local Event-fold cache (`delivered`).
        // A cache write failure never affects the accepted exchange (§7.2).
        crate::sidecar::remove_pending_sidecar_submission(
            &mut store,
            controller_id,
            private_strand_id,
            &intent_digest,
        );
        if let Err(error) = crate::sidecar::record_accepted_sidecar_exchange_request(
            &mut store, &pending, &event_id,
        ) {
            tracing::warn!(%error, "Sidecar exchange fold cache write is pending a refold");
        }
    }
    Ok(SourceRoutedSidecarMessageOutcome { event_id })
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
async fn ensure_sidecar_mls_bootstrap(
    base_url: &str,
    api_token: String,
    controller_id: &str,
    device_id: &str,
    mut state_store: SyncSignal<LocalStateStore>,
    view: arkret_sdk::AgentSidecarView,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    view.validate()?;
    let realm_id = view.sidecar.realm_id.to_string();
    let circle_id = view.sidecar.backing_circle_id.to_string();
    let binding = sidecar_mls_binding(&view);

    if let (Some(server_group_id), Some(genesis_event_ref)) = (
        view.mls_context.mls_group_id.as_ref(),
        view.mls_context.genesis_event_ref.as_ref(),
    ) {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let local_summary = crate::mls::runtime::initial_mls_snapshot_summary_from_existing_for_effective_scope_with_binding(
            &state_store.read(),
            secure_store.as_ref(),
            &realm_id,
            Some(&circle_id),
            controller_id,
            device_id,
            Some(binding),
        );
        match local_summary {
            Ok(Some(summary)) if summary.group_id != server_group_id.as_str() => {
                let mut store = state_store.write();
                store.drop_mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id));
                store.clear_pending_mls_genesis_event_for_effective_scope(
                    &realm_id,
                    Some(&circle_id),
                );
            }
            Ok(Some(_)) => state_store
                .write()
                .mark_mls_genesis_emitted_for_effective_scope_with_event(
                    realm_id,
                    Some(&circle_id),
                    genesis_event_ref,
                ),
            Ok(None) => {}
            Err(error) => {
                let mut store = state_store.write();
                store.drop_mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id));
                store.clear_pending_mls_genesis_event_for_effective_scope(
                    &realm_id,
                    Some(&circle_id),
                );
                tracing::warn!(target: "sidecar", "discarded unusable provisional Sidecar MLS snapshot: {}", error.user_message());
            }
        }
        return Ok(view);
    }

    if view.pending_access_reconciliations.iter().any(|item| {
        item.provisioning_phase
            == arkret_sdk::PendingSidecarAccessReconciliationStage::BackingScopeMembership
    }) {
        return Ok(view);
    }

    let summary = {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let mut store = state_store.write();
        let fresh =
            crate::mls::runtime::ensure_creator_mls_snapshot_for_effective_scope_with_binding(
                &mut store,
                secure_store.as_ref(),
                &realm_id,
                Some(&circle_id),
                controller_id,
                device_id,
                Some(binding.clone()),
            )
            .map_err(|error| anyhow::anyhow!(error.user_message()))?;
        let restored = match fresh {
            Some(summary) => Ok(Some(summary)),
            None => crate::mls::runtime::initial_mls_snapshot_summary_from_existing_for_effective_scope_with_binding(
                &store,
                secure_store.as_ref(),
                &realm_id,
                Some(&circle_id),
                controller_id,
                device_id,
                Some(binding.clone()),
            ),
        };
        let restored = match restored {
            Ok(summary) => summary,
            Err(_) => {
                store.drop_mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id));
                store.clear_pending_mls_genesis_event_for_effective_scope(
                    &realm_id,
                    Some(&circle_id),
                );
                crate::mls::runtime::ensure_creator_mls_snapshot_for_effective_scope_with_binding(
                    &mut store,
                    secure_store.as_ref(),
                    &realm_id,
                    Some(&circle_id),
                    controller_id,
                    device_id,
                    Some(binding.clone()),
                )
                .map_err(|error| anyhow::anyhow!(error.user_message()))?
            }
        };
        restored.ok_or_else(|| anyhow::anyhow!("Sidecar MLS epoch-0 snapshot is unavailable"))?
    };
    let pending = state_store
        .read()
        .pending_mls_genesis_event_for_effective_scope(&realm_id, Some(&circle_id));
    let pending_matches = pending.as_ref().is_some_and(|event| {
        event.payload.get("mls_group_id").and_then(Value::as_str) == Some(summary.group_id.as_str())
            && event
                .payload
                .get("governance_binding")
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<arkret_sdk::MlsGovernanceBindingPayload>(value).ok()
                })
                .and_then(|value| value.sidecar_binding().cloned())
                .as_ref()
                == Some(&binding)
    });
    let unsigned_or_pending = if pending_matches {
        pending.expect("presence checked")
    } else {
        state_store
            .write()
            .clear_pending_mls_genesis_event_for_effective_scope(&realm_id, Some(&circle_id));

        crate::mls::group_events::build_creator_mls_genesis_event_for_effective_scope_with_binding(
            &mut state_store.write(),
            &realm_id,
            Some(&circle_id),
            controller_id,
            device_id,
            Some(&summary),
            Some(binding),
        )
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| {
            anyhow::anyhow!("Sidecar MLS genesis is not accepted but local state marks it emitted")
        })?
    };
    let genesis = if unsigned_or_pending.proofs.is_empty() {
        let event = crate::transport::auth::with_authed_api(
            base_url,
            api_token.clone(),
            move |api| async move {
                api.event_submitter()?
                    .prepare_sdk_event_for_submit(&unsigned_or_pending)
                    .await
                    .map(|(event, _)| event)
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
        state_store
            .write()
            .save_pending_mls_genesis_event_for_effective_scope(
                &realm_id,
                Some(&circle_id),
                event.clone(),
            )?;
        event
    } else {
        unsigned_or_pending
    };

    let submitted = crate::transport::auth::with_authed_api(base_url, api_token.clone(), |api| {
        let genesis = genesis.clone();
        let summary = summary.clone();
        async move {
            crate::mls::runtime::upload_mls_genesis_public_material(&api, &summary)
                .await
                .map_err(|error| anyhow::anyhow!(error.user_message()))?;
            api.event_submitter()?
                .submit_signed_sdk_event(&genesis)
                .await
        }
    })
    .await;
    let refreshed = crate::transport::auth::with_authed_sdk_client(base_url, api_token, |http| {
        let sidecar_id = view.sidecar.id.clone();
        async move {
            http.agent_sidecar_get(&sidecar_id)
                .await
                .map_err(anyhow::Error::from)
        }
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))?;
    let accepted_group_id = refreshed
        .mls_context
        .mls_group_id
        .as_ref()
        .map(ToString::to_string);
    if accepted_group_id.as_deref() != Some(summary.group_id.as_str()) {
        let mut store = state_store.write();
        store.drop_mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id));
        store.clear_pending_mls_genesis_event_for_effective_scope(&realm_id, Some(&circle_id));
        if accepted_group_id.is_some() {
            return Ok(refreshed);
        }
        return Err(submitted
            .err()
            .map(|error| anyhow::anyhow!(error.display()))
            .unwrap_or_else(|| anyhow::anyhow!("accepted Sidecar MLS genesis is not projected")));
    }
    submitted.map_err(|error| anyhow::anyhow!(error.display()))?;
    state_store
        .write()
        .mark_mls_genesis_emitted_for_effective_scope_with_event(
            realm_id,
            Some(&circle_id),
            &genesis.event_id,
        );
    Ok(refreshed)
}

fn sidecar_agent_label(agent_ids: &[String], participants: &[SpaceParticipant]) -> String {
    let labels = agent_ids
        .iter()
        .map(|agent_id| {
            participants
                .iter()
                .find(|participant| participant.did == *agent_id)
                .and_then(|participant| {
                    participant
                        .agent_metadata
                        .as_ref()
                        .map(|metadata| metadata.agent_slug.trim())
                        .filter(|slug| !slug.is_empty())
                        .map(ToOwned::to_owned)
                        .or_else(|| participant.handle_label.clone())
                })
                .unwrap_or_else(|| {
                    agent_id
                        .rsplit([':', '/'])
                        .next()
                        .filter(|value| !value.is_empty())
                        .unwrap_or("Agent")
                        .to_owned()
                })
        })
        .collect::<Vec<_>>();
    match labels.as_slice() {
        [] => "AI Sidecar".to_owned(),
        [label] => label.clone(),
        _ => format!("{} + {} agents", labels[0], labels.len() - 1),
    }
}

fn composer_mention_nodes(
    mentions_enabled: bool,
    body: &str,
    picker: &[crate::messaging::mentions::MentionCandidate],
    account_did: &str,
) -> Vec<MentionNode> {
    if !mentions_enabled {
        return Vec::new();
    }
    let mut mentions = parse_mention_nodes(body);
    for chip in picker {
        if mentions.iter().any(|node| {
            node.as_mention()
                .is_some_and(|mention| mention.subject_id.as_str() == chip.did)
        }) {
            continue;
        }
        let Ok(subject_id) = arkret_sdk::Did::new(chip.did.clone()) else {
            continue;
        };
        // `@me/<slug>` is allowed into the draft before the signed account
        // primary handle finishes loading. Do not turn that incomplete chip
        // into a generic actor mention; the send path resolves the selector
        // once the authoritative controller handle is available.
        if chip.is_agent
            && (chip.controller_subject_id.trim().is_empty()
                || chip.controller_handle_at_time.trim().is_empty()
                || chip.agent_slug_at_time.trim().is_empty())
        {
            continue;
        }
        let insert_label = chip.insert_label().to_owned();
        let parsed_handle = (!chip.is_agent)
            .then(|| crate::identity::handle::parse_user_handle(&insert_label))
            .flatten();
        let mut mention = arkret_sdk::Mention::new(subject_id)
            .with_mention_text_original(format!("@{insert_label}"));
        if !chip.display_name.trim().is_empty() {
            mention = mention.with_display_name_at_time(chip.display_name.clone());
        }
        if let Some(handle) =
            parsed_handle.and_then(|parsed| arkret_sdk::Handle::parse(&parsed.handle).ok())
        {
            mention = mention.with_handle_at_time(handle);
        }
        if let (Ok(controller_subject_id), Ok(controller_handle)) = (
            arkret_sdk::Did::new(chip.controller_subject_id.clone()),
            arkret_sdk::Handle::parse(&chip.controller_handle_at_time),
        ) && !chip.agent_slug_at_time.trim().is_empty()
        {
            mention = mention.with_agent_selector_metadata(
                controller_subject_id,
                controller_handle,
                chip.agent_slug_at_time.clone(),
            );
        }
        mentions.push(MentionNode::mention(mention));
    }
    if crate::messaging::mentions::contains_self_mention_token(body)
        && !mentions.iter().any(|node| {
            node.as_mention()
                .is_some_and(|mention| mention.subject_id.as_str() == account_did.trim())
        })
        && let Ok(subject_id) = arkret_sdk::Did::new(account_did.trim().to_owned())
    {
        mentions.push(MentionNode::mention(
            arkret_sdk::Mention::new(subject_id).with_mention_text_original("@me".to_owned()),
        ));
    }
    mentions
}

/// Attach the §4.5 E2EE mention-routing sidecar to an outgoing
/// `ak.message.create`.
///
/// `routing_key` is the Realm's current-epoch mention routing key. It is
/// `None` whenever the sidecar must not be produced — a plaintext Realm, a
/// Realm whose effective `mention_routing_hint` is `disabled`, or a device
/// that cannot reach its MLS group — and the event then goes out with no
/// sidecar rather than with a tag derived from anything else.
fn apply_mention_sidecar_digestes(
    event: &mut arkret_sdk::Event,
    mentions: &[MentionNode],
    routing_key: Option<&[u8]>,
) {
    let mention_dids = mentions
        .iter()
        .filter_map(|node| {
            node.as_mention()
                .map(|mention| mention.subject_id.as_str().to_owned())
        })
        .collect::<Vec<_>>();
    if mention_dids.is_empty() {
        return;
    }
    let Some(routing_key) = routing_key else {
        return;
    };
    let Ok(digests) =
        crate::messaging::mentions::mention_sidecar_digestes(routing_key, &mention_dids)
    else {
        return;
    };
    // `event-payload.schema.json#/$defs/message_create_payload` puts
    // `mention_sidecar_digest` at the payload root and closes the object, so
    // nesting it under `content` would be a schema violation, not a variant.
    event.payload.insert(
        "mention_sidecar_digest".to_owned(),
        Value::Array(digests.into_iter().map(Value::String).collect()),
    );
}

fn chat_visible_read_receipt_should_send(
    store: &LocalStateStore,
    strand_id: &str,
    realm_id: &str,
) -> bool {
    let strand_id = strand_id.trim();
    let realm_id = realm_id.trim();
    store.read_receipt_should_send(
        (!strand_id.is_empty()).then_some(strand_id),
        (!realm_id.is_empty()).then_some(realm_id),
    )
}

fn chat_visible_read_receipt_should_display(
    store: &LocalStateStore,
    strand_id: &str,
    realm_id: &str,
) -> bool {
    let strand_id = strand_id.trim();
    let realm_id = realm_id.trim();
    store.read_receipt_should_display(
        (!strand_id.is_empty()).then_some(strand_id),
        (!realm_id.is_empty()).then_some(realm_id),
    )
}

fn should_start_circle_scope_request(
    credential: &str,
    request_key_seen: &str,
    request_in_flight: bool,
    request_key: &str,
) -> bool {
    !credential.trim().is_empty() && !request_in_flight && request_key_seen != request_key
}

#[component]
pub fn ChatPanel(
    plaintext_service_id: String,
    account_did: String,
    account_primary_handle: String,
    device_id: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    /// Monotonic counter bumped by the per-realm `events/subscribe` engine
    /// when it folds fresh realm events into `raw_operations`. Chat must
    /// observe it because cross-member discussion events can arrive through the
    /// realm stream without advancing the account aggregate cursor.
    realm_live_epoch: Signal<u64>,
    frontier_state: Signal<String>,
    initial_strand_id: String,
    embedded: bool,
    direct_mode: bool,
    /// Counterpart resolved by the contact-only Direct Conversation entry
    /// point. It is display identity, not participation authorization: an
    /// Agent remains the conversation peer even when reply enablement is
    /// unavailable.
    #[props(default)]
    direct_peer_id: String,
    /// Present only when `/direct/...` was reached through the standard
    /// Agent Sidecar ensure flow. Contact DMs continue to use direct mode
    /// without receiving Sidecar-specific membership semantics.
    #[props(default)]
    sidecar_session: Option<crate::sidecar::HostedSidecarState>,
    /// Optional deep-link target: when non-empty, the message with this id is
    /// scrolled into view and flashed on mount (design/route-view-ia.md §3.2).
    #[props(default)]
    focus_message_id: String,
    mention_insert_request: Option<Signal<Option<MentionInsertRequest>>>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let mut sidecar_session_state = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    // Embedded Strand shells do not receive a route-owned Sidecar prop. Read
    // the same hosted session that renders the context bar so message
    // projection, privacy gates, and the composer cannot diverge after an
    // in-place activation.
    let hosted_sidecar_session = sidecar_session_state();
    let sidecar_session = sidecar_session.or_else(|| {
        hosted_sidecar_session
            .filter(|session| session.matches_route(&selected_realm_id, &initial_strand_id))
    });
    let navigator = use_navigator();
    let controller = use_chat_controller(&selected_realm_id, &initial_strand_id, &account_did);
    let mut migrated_draft_applied_for = use_signal(String::new);
    let mut sidecar_exchange_fold_basis_seen = use_signal(String::new);
    let sidecar_close_retry_epoch = use_signal(|| 0_u64);
    let mut member_handle_fetching = use_signal(std::collections::BTreeSet::<String>::new);
    {
        let handle_base_url = base_url.clone();
        let handle_realm_id = selected_realm_id.clone();
        use_effect(move || {
            let _account_cursor = sync_cursor();
            let _realm_epoch = realm_live_epoch();
            let api_token = token();
            if handle_base_url.trim().is_empty()
                || handle_realm_id.trim().is_empty()
                || api_token.trim().is_empty()
            {
                return;
            }
            let projection = state_store
                .read()
                .load()
                .realm_tree_projections
                .get(&handle_realm_id)
                .cloned();
            let rows = crate::views::member_display::realm_member_roster(projection.as_ref());
            if rows.is_empty() {
                return;
            }
            let fetches = {
                let store = state_store.read();
                let in_flight = member_handle_fetching.read();
                crate::views::member_display::missing_member_handle_lookups(
                    &store,
                    &handle_realm_id,
                    &rows,
                    &in_flight,
                )
            };
            for request in fetches {
                let request_key = request.request_key.clone();
                member_handle_fetching.write().insert(request_key.clone());
                let base = handle_base_url.clone();
                let credential = api_token.clone();
                let store = state_store;
                let mut fetching = member_handle_fetching;
                spawn(async move {
                    crate::views::member_display::fetch_and_cache_member_handle(
                        base, credential, store, request,
                    )
                    .await;
                    fetching.write().remove(&request_key);
                });
            }
        });
    }
    {
        let actor = account_did.clone();
        let state_store = state_store;
        use_effect(move || {
            let _account_cursor = sync_cursor();
            let Some(mut session) = sidecar_session_state() else {
                return;
            };
            let Some(remote_mode) =
                crate::sidecar::cached_sidecar_display_mode(&state_store.read(), &actor, &session)
            else {
                return;
            };
            if session.display_mode != remote_mode {
                session.display_mode = remote_mode;
                sidecar_session_state.set(Some(session));
            }
        });
    }
    {
        let session = sidecar_session.clone();
        let mut draft = controller.draft;
        use_effect(move || {
            let Some(session) = session.as_ref() else {
                return;
            };
            if session.migrated_draft.trim().is_empty()
                || migrated_draft_applied_for.peek().as_str() == session.trace_id
            {
                return;
            }
            draft.set(session.migrated_draft.clone());
            migrated_draft_applied_for.set(session.trace_id.clone());
        });
    }
    let ChatController {
        mut channels,
        selected_channel,
        messages,
        moderation_appeal_prompts,
        draft: _,
        typing_throttle: _,
        compose_dragover: _,
        compose_upload_status: _,
        shared_pins,
        private_saved_targets: _,
        private_saved_account_data: _,
        message_context_menu: _,
        mut new_channel_name,
        mut new_channel_topic,
        mut new_channel_create_card,
        mut create_dialog_open,
        mut strand_watch_level,
        mut watch_level_menu_open,
        mut status_msg,
        queued_outbound_message_ids,
        is_online,
        reply_to_message: _,
        editing_message: _,
        edit_draft: _,
        redact_confirm: _,
        reaction_picker: _,
        initial_sync_requested: _,
        initial_sync_finished,
        mention_picker_state: _,
        owned_agent_slugs,
        owned_agent_sync_key_seen: _,
        agent_participation_visibility,
        agent_participation_sync_key_seen: _,
        attachment_menu_open: _,
        poll_draft: _,
        poll_cards: _,
        typing_actors,
        typing_next_expires_at_ms: _,
        presence_states,
        presence_labels,
        presence_status_messages,
        presence_sync_key_seen: _,
        presence_announce_key_seen: _,
        presence_heartbeat_tick: _,
        mut promote_discussion_draft,
        mut promoted_targets,
        latest_read_cursor: _,
        blocked_show_anyway: _,
        account_display_name,
        mut track_filter,
        mut left_panel_open,
    } = controller;
    let mut eligible_circle_scopes = use_signal(Vec::<CircleSummary>::new);
    let mut eligible_circle_scope_request_key_seen = use_signal(String::new);
    let mut eligible_circle_scope_request_in_flight = use_signal(|| false);
    let mut new_channel_scope = use_signal(CircleScope::default);
    let mut sidecar_publish_open = use_signal(|| false);
    let mut sidecar_publish_draft = use_signal(String::new);
    let mut sidecar_publish_pending = use_signal(|| false);
    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let actor = account_did.clone();
        use_effect(move || {
            let credential = token();
            let base = base.clone();
            let realm = realm.clone();
            let request_key = format!("{base}\u{1f}{actor}\u{1f}{realm}");
            if !should_start_circle_scope_request(
                &credential,
                eligible_circle_scope_request_key_seen.peek().as_str(),
                *eligible_circle_scope_request_in_flight.peek(),
                &request_key,
            ) {
                return;
            }
            eligible_circle_scope_request_key_seen.set(request_key.clone());
            eligible_circle_scope_request_in_flight.set(true);
            spawn(async move {
                let outcome =
                    crate::transport::auth::with_authed_api(&base, credential, |api| async move {
                        api.http()
                            .circle_list(&realm)
                            .await
                            .map_err(anyhow::Error::from)
                    })
                    .await;
                match outcome {
                    Ok(list) => {
                        let summaries = crate::circle::ordinary_circle_views(list)
                            .into_iter()
                            .filter(|circle| {
                                circle.state == arkret_sdk::CircleState::Active
                                    && circle.viewer_membership
                                        == Some(arkret_sdk::CircleMembership::Join)
                                    && circle.pending_mls_removals.is_empty()
                            })
                            .map(|circle| CircleSummary {
                                id: circle.circle_id.to_string(),
                                realm_id: circle.realm_id.to_string(),
                                title: circle.title,
                                short_name: circle.display.short_name,
                                color_token: format!("{:?}", circle.display.color_token),
                                symbol: format!("{:?}", circle.display.symbol),
                                member_count: circle.member_count.unwrap_or(0),
                                state: circle.state,
                                viewer_is_member: true,
                            })
                            .collect();
                        eligible_circle_scopes.set(summaries);
                    }
                    Err(error) => {
                        if eligible_circle_scope_request_key_seen.peek().as_str() == request_key {
                            // Permit a later credential/context change to retry,
                            // but do not immediately self-trigger this effect.
                            eligible_circle_scope_request_key_seen.set(String::new());
                        }
                        tracing::warn!(
                            error = %error.display(),
                            "Circle scope picker load failed"
                        );
                    }
                }
                eligible_circle_scope_request_in_flight.set(false);
            });
        });
    }
    let blocked_did_set: std::collections::BTreeSet<String> = state_store
        .read()
        .client_blocklist()
        .into_iter()
        .filter(crate::account_data::hides_actor_messages)
        .map(|entry| crate::account_data::blocklist_target_value(&entry.target).to_owned())
        .collect();
    let sidecar_mode = sidecar_session.is_some();
    let mut right_panel = use_signal(move || {
        if sidecar_mode {
            None
        } else {
            Option::<DiscussionSidePanel>::Some(DiscussionSidePanel::Users)
        }
    });
    let selected_channel_value = selected_channel();
    let all_channels = channels();
    let mut private_sidecar_strand_ids = all_channels
        .iter()
        .filter(|channel| channel.is_private_sidecar)
        .map(|channel| channel.strand_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(session) = sidecar_session.as_ref() {
        private_sidecar_strand_ids.insert(session.private_strand_id.clone());
    }
    let sidecar_exchange_projections = crate::sidecar::cached_sidecar_exchange_projections(
        &state_store.read(),
        &account_did,
        &selected_realm_id,
    );
    for projection in &sidecar_exchange_projections {
        private_sidecar_strand_ids.insert(projection.private_strand_id.to_string());
    }
    let sidecar_privacy_gate =
        crate::sidecar::SidecarPrivacyGate::from_store(&state_store.read(), &account_did);
    let filter_value = track_filter();
    let visible_channels: Vec<ChannelEntity> = all_channels
        .iter()
        .filter(|channel| {
            filter_value == "with_discussion_track"
                || channel.is_default
                || channel.kind == "discussion"
        })
        .cloned()
        .collect();
    let visible_channels_empty = visible_channels.is_empty();
    let selected_channel_info = visible_channels
        .iter()
        .find(|channel| channel.strand_id == selected_channel_value)
        .cloned()
        .or_else(|| visible_channels.first().cloned());
    let selected_channel_name = if embedded {
        "Discussion".to_owned()
    } else {
        selected_channel_info
            .as_ref()
            .map(|channel| channel.name.clone())
            .unwrap_or_else(|| crate::i18n::tr("chat.empty.title"))
    };
    let selected_channel_category = selected_channel_info
        .as_ref()
        .map(|channel| channel.category.clone())
        .unwrap_or_else(|| "discussion".to_owned());
    let selected_channel_unread = selected_channel_info
        .as_ref()
        .filter(|channel| {
            sidecar_privacy_gate.allows_strand(
                crate::sidecar::SidecarDisclosureSurface::Unread,
                &channel.strand_id,
            )
        })
        .map(|channel| channel.unread)
        .unwrap_or(0);
    let selected_realm_security_encrypted = {
        let state = state_store.read().load();
        crate::security_state::security_projection_for_scope_id(
            &state.realm_tree_projections,
            &selected_realm_id,
        )
        .map(crate::security_state::realm_projection_is_encrypted)
        .unwrap_or(false)
    };
    // The first-class Sidecar contract requires an independent MLS backing scope.
    // The private Strand only carries its internal scope id, so ordinary Realm
    // inheritance would incorrectly downgrade a Sidecar opened from a
    // plaintext principal-control Realm and expose the plaintext Send path.
    let selected_channel_security_encrypted = if sidecar_mode {
        true
    } else {
        selected_channel_info
            .as_ref()
            .and_then(|channel| channel.security_encrypted)
            .unwrap_or(selected_realm_security_encrypted)
    };
    let mut selected_realm_pending_mls_binding_reason = state_store
        .read()
        .realm_pending_mls_binding_reason(&selected_realm_id);
    if selected_realm_security_encrypted
        && !sidecar_mode
        && selected_realm_pending_mls_binding_reason.is_none()
    {
        if state_store
            .read()
            .realm_content_scheme(&selected_realm_id)
            .is_none()
        {
            selected_realm_pending_mls_binding_reason = Some(
                "encryption_policy_pending: waiting for the verified content scheme".to_owned(),
            );
        } else {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let roster_matches =
                crate::mls::runtime::realm_mls_roster_matches_complete_membership_hint(
                    &state_store.read(),
                    secure_store.as_ref(),
                    &selected_realm_id,
                    &account_did,
                    &device_id,
                );
            if roster_matches == Some(false) {
                selected_realm_pending_mls_binding_reason = Some(
                    "encryption_transition_pending: synced roster differs from the verified MLS group"
                        .to_owned(),
                );
            }
        }
    }
    let selected_realm_pending_mls_binding = selected_realm_pending_mls_binding_reason.is_some();
    let sidecar_security_label = sidecar_session.as_ref().map(|session| {
        if !session.membership_ready() {
            "Reconciling access"
        } else if selected_channel_security_encrypted && selected_realm_pending_mls_binding {
            "Preparing encryption"
        } else if selected_channel_security_encrypted {
            "E2EE"
        } else {
            "Encryption unavailable"
        }
    });
    let sidecar_send_block_reason = sidecar_session.as_ref().and_then(|session| {
        if !session.membership_ready() {
            Some(format!(
                "Private access is still reconciling for {} principal(s). Sending is disabled until backing scope and MLS access are ready.",
                session.pending_reconciliation_count()
            ))
        } else if selected_channel_security_encrypted && selected_realm_pending_mls_binding {
            Some(
                "Encryption membership is still being prepared. Sending is disabled until this device and the addressed Agent are ready."
                    .to_owned(),
            )
        } else {
            None
        }
    });
    // Fold the durable lifecycle log directly onto the controller's
    // optimistic rows. A sender's create can still be controller-only when a
    // remote reaction arrives, so projecting raw operations in isolation
    // would discard that control event for lack of a target message.
    // Folding the complete durable operation log is intentionally memoized.
    // Presence heartbeats, panel toggles, typing timers, and composer changes
    // all re-render ChatPanel; repeating the full lifecycle fold on each of
    // those unrelated edges can monopolize the WASM main thread once an
    // account has a substantial history, making the entire browser appear
    // hung even though network traffic stays quiet.
    let all_messages_snapshot = use_memo({
        let account_did = account_did.clone();
        let device_id = device_id.clone();
        move || {
            // These are the durable invalidation edges. `peek` below avoids
            // treating unrelated LocalStateStore writes (backup metadata,
            // settings, presence preferences) as a timeline invalidation.
            let _account_cursor = sync_cursor();
            let _realm_epoch = realm_live_epoch();
            let store = state_store.peek();
            let snapshot = store.load();
            let decrypt_identity = Some((account_did.as_str(), device_id.as_str()));
            let mut folded = fold_local_state_into_chat_messages_with_sidecar(
                messages(),
                &snapshot,
                Some(&store),
                decrypt_identity,
            );
            // Account sync also carries the server-folded timeline (notably a
            // revise event rewritten into a redacted create tombstone). Merge
            // it after local controls so an older revision cannot win.
            let server_folded = chat_messages_from_sync_realms_with_sidecar(
                &snapshot.realm_tree_projections,
                Some(&store),
                decrypt_identity,
            );
            merge_chat_messages(&mut folded, server_folded);
            folded
        }
    });
    {
        let close_base_url = base_url.clone();
        let account_did = account_did.clone();
        let device_id = device_id.clone();
        let selected_realm_id = selected_realm_id.clone();
        let all_messages_for_fold = all_messages_snapshot;
        let active_sidecar = sidecar_session.clone();
        let session_scope_hints = sidecar_session
            .as_ref()
            .map(|session| {
                vec![crate::sidecar::SidecarExchangeScopeHint {
                    private_strand_id: session.private_strand_id.clone(),
                    sidecar_id: session.sidecar_id.clone(),
                    backing_circle_id: session.backing_scope_circle_id.clone(),
                }]
            })
            .unwrap_or_default();
        use_effect(move || {
            let cursor = sync_cursor();
            let realm_epoch = realm_live_epoch();
            let close_retry_epoch = sidecar_close_retry_epoch();
            // Accepted rows keyed by protocol message id: a pending
            // submission whose request Event landed (e.g. the cache write
            // raced a crash) is recognised by its message id and folded to
            // `delivered` — the Event-truth successor of the old
            // "Pending → Delivered" account-data retry.
            let accepted_event_by_message_id = all_messages_for_fold
                .read()
                .iter()
                .filter(|message| !message.pending && !message.failed)
                .filter_map(|message| {
                    message
                        .protocol_message_id
                        .clone()
                        .map(|message_id| (message_id, message.id.clone()))
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            let basis = format!("{cursor}\u{1f}{realm_epoch}\u{1f}{close_retry_epoch}");
            if sidecar_exchange_fold_basis_seen.peek().as_str() == basis {
                return;
            }
            sidecar_exchange_fold_basis_seen.set(basis);
            let mut store = state_store.write();
            for (key, pending) in crate::sidecar::pending_sidecar_submissions(&store, &account_did)
            {
                let Some(accepted_event_id) = accepted_event_by_message_id.get(&pending.message_id)
                else {
                    continue;
                };
                store.remove_private_data(&key);
                if let Err(error) = crate::sidecar::record_accepted_sidecar_exchange_request(
                    &mut store,
                    &pending,
                    accepted_event_id,
                ) {
                    tracing::warn!(%error, "accepted Sidecar request fold cache write failed");
                }
            }
            // Receive-side Event-truth fold: decrypt exchange bindings and
            // durable control Events from the synced private-Strand history
            // and refresh the local fold cache (`zh/models/sidecar.md` §7.2.4).
            crate::sidecar::refold_sidecar_exchanges_from_history(
                &mut store,
                &account_did,
                &device_id,
                &selected_realm_id,
                &session_scope_hints,
            );
            let retryable_closes = crate::sidecar::pending_sidecar_auto_close_intents(
                &store,
                &account_did,
                &selected_realm_id,
            )
            .into_iter()
            .filter(|intent| intent.accepted_control_event_id.is_none())
            .collect::<Vec<_>>();
            drop(store);
            let Some(session) = active_sidecar.as_ref() else {
                return;
            };
            let Ok(sidecar_binding) = session.mls_binding() else {
                return;
            };
            for intent in retryable_closes {
                if intent.private_strand_id != session.private_strand_id
                    || intent.sidecar_id != session.sidecar_id
                    || intent.backing_circle_id != session.backing_scope_circle_id
                {
                    continue;
                }
                let base = close_base_url.clone();
                let credential = token();
                let device = device_id.clone();
                let binding = sidecar_binding.clone();
                let store = state_store;
                let mut retry_epoch = sidecar_close_retry_epoch;
                spawn(async move {
                    if let Err(error) = crate::sidecar::submit_pending_sidecar_auto_close(
                        &base, credential, &device, store, intent, binding,
                    )
                    .await
                    {
                        tracing::warn!(%error, "Sidecar durable auto-close submit failed; retry scheduled");
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(2)).await;
                        retry_epoch.set(retry_epoch().wrapping_add(1));
                    }
                });
            }
        });
    }
    let all_messages_snapshot = all_messages_snapshot.read().clone();
    let sidecar_projection = sidecar_session.as_ref().map(|session| {
        (
            session.source_strand_id.as_str(),
            session.private_strand_id.as_str(),
            session.display_mode,
        )
    });
    let visible_messages = project_visible_messages(
        &all_messages_snapshot,
        &selected_channel_value,
        &selected_realm_id,
        sidecar_projection,
        &sidecar_exchange_projections,
    );
    let visible_moderation_appeal_prompts = moderation_appeal_prompts()
        .into_iter()
        .filter(|prompt| {
            selected_realm_id.trim().is_empty() || prompt.realm_id == selected_realm_id
        })
        .collect::<Vec<_>>();
    let visible_moderation_appeal_prompt_count = visible_moderation_appeal_prompts.len();
    // Dioxus may retain the child timeline across context-backed signal updates. Key the
    // projection boundary by every visible timeline row so message and moderation lifecycle
    // folds cannot leave a memoized child rendering an older snapshot.
    let _timeline_projection_key = timeline_projection_key(
        &selected_realm_id,
        realm_live_epoch(),
        &visible_messages,
        &visible_moderation_appeal_prompts,
        &private_sidecar_strand_ids,
    );
    // AKP-0007 P3B.2.4 — per-strand Circle-scope lookup used by the
    // message accent rail. We index by `strand_id` once instead of
    // searching the `channels` Vec for every rendered message.
    let strand_scope_lookup: std::collections::BTreeMap<String, StrandScopeCircle> = all_channels
        .iter()
        .filter_map(|channel| {
            channel
                .scope_circle
                .clone()
                .map(|circle| (channel.strand_id.clone(), circle))
        })
        .collect();
    let visible_message_count = visible_messages.len();
    let latest_sidecar_publish_body = sidecar_session.as_ref().and_then(|session| {
        visible_messages
            .iter()
            .rev()
            .find(|message| {
                message.strand_id == session.private_strand_id
                    && !message.redacted
                    && !message.body.trim().is_empty()
            })
            .map(|message| message.body.clone())
    });
    let messages_for_reply_lookup = &all_messages_snapshot;
    let left_open = !embedded && !direct_mode && left_panel_open();
    let active_right_panel = if embedded { None } else { right_panel() };
    let right_open = active_right_panel.is_some();
    let shell_class = format!(
        "discussion-shell{}{}{}{}{}",
        if embedded { " embedded" } else { "" },
        if direct_mode { " direct-mode" } else { "" },
        if sidecar_mode { " sidecar-mode" } else { "" },
        if left_open { "" } else { " left-collapsed" },
        if right_open { "" } else { " right-collapsed" }
    );
    let participant_projection = state_store
        .read()
        .load()
        .realm_tree_projections
        .get(&selected_realm_id)
        .cloned();
    let account_display_label = account_display_name();
    let mut participants = space_participants(
        participant_projection.as_ref(),
        &state_store.read(),
        &selected_realm_id,
        &account_did,
    );
    let direct_peer_id = if direct_mode {
        crate::transport::account::cached_direct_conversation_peer(
            &state_store.read(),
            &selected_realm_id,
            &initial_strand_id,
        )
        .unwrap_or(direct_peer_id)
    } else {
        String::new()
    };
    let projected_member_dids = participants
        .iter()
        .map(|participant| participant.did.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let own_controller_handle = participants
        .iter()
        .find(|participant| participant.is_self && !participant.is_agent)
        .and_then(mention_label_for_participant);
    // Agent identity comes from the controller-owned inventory. Mention
    // selector fields are persistent audit snapshots and may only enrich an
    // already-authoritative agent; they never promote an arbitrary DID to an
    // agent. This keeps the roster fail-closed when profile, selector-claim,
    // and accountability evidence is unavailable.
    {
        let mut agent_metadata = owned_agent_metadata(
            &owned_agent_slugs(),
            &account_did,
            own_controller_handle.as_deref(),
        );
        enrich_authoritative_agent_metadata(
            &mut agent_metadata,
            agent_metadata_from_mentions(&all_messages_snapshot),
        );
        upsert_agent_participants(&mut participants, &agent_metadata, &account_did);
        annotate_agent_participants_with_metadata(&mut participants, &agent_metadata);
    }
    let participants_for_messages = participants.clone();

    let mut known_agent_ids = participants_for_messages
        .iter()
        .filter(|participant| participant.is_agent)
        .map(|participant| participant.did.clone())
        .collect::<Vec<_>>();
    known_agent_ids.sort();
    known_agent_ids.dedup();
    // The participation resource is controller-self-only. Remote agents are
    // never probed here; they become roster-visible only through already
    // visible reply history, which avoids both forbidden requests and agent
    // policy enumeration.
    let readable_participation_agent_ids =
        readable_participation_agent_ids(&participants_for_messages, &account_did);
    let selected_scope_circle = channels()
        .iter()
        .find(|channel| channel.strand_id == selected_channel_value)
        .and_then(|channel| {
            channel
                .scope_circle
                .as_ref()
                .map(|circle| circle.circle_id.clone())
        });
    // Participation is a durable Realm projection. The account cursor is an
    // opaque resume checkpoint and can be re-minted for typing/receipts/calls;
    // reduce it to the one useful transition (bootstrap is ready) and use the
    // Realm epoch for subsequent durable invalidation.
    let account_sync_ready = {
        let cursor = sync_cursor();
        let cursor = cursor.trim();
        !(cursor.is_empty() || cursor == "-")
    };
    let agent_participation_sync_key = format!(
        "{}|{}|{}|{}|{}|{}",
        selected_realm_id,
        selected_channel_value,
        selected_scope_circle.as_deref().unwrap_or_default(),
        account_sync_ready as u8,
        realm_live_epoch(),
        readable_participation_agent_ids.join(",")
    );
    let mut public_agent_dids = std::collections::BTreeSet::new();
    public_agent_dids.extend(
        agent_participation_visibility()
            .into_iter()
            .filter_map(|(agent_id, visible)| visible.then_some(agent_id)),
    );
    let known_agent_did_set = known_agent_ids
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    public_agent_dids.extend(
        visible_messages
            .iter()
            .filter(|message| message.reply_to.is_some())
            .map(|message| message.sender.trim())
            .filter(|sender| known_agent_did_set.contains(sender))
            .map(ToOwned::to_owned),
    );
    // A Sidecar's membership boundary is controller-private and the server
    // ensure operation already admits every eligible owned Agent. Do not run
    // those Agents through the public-participation filter used by ordinary
    // Realm discussions; doing so hid the exact principals that make up this
    // private Circle and left the panel showing only the controller.
    if sidecar_mode {
        public_agent_dids.extend(known_agent_ids.iter().cloned());
    }
    if direct_mode {
        public_agent_dids.extend(
            known_agent_ids
                .iter()
                .filter(|agent_id| {
                    direct_agent_is_conversation_peer(
                        agent_id,
                        &direct_peer_id,
                        &projected_member_dids,
                    )
                })
                .cloned(),
        );
    }
    participants.retain(|participant| {
        !participant.is_agent || public_agent_dids.contains(&participant.did)
    });
    let sidecar_owned_agents = sidecar_owned_agent_participants(&participants, &account_did);
    // Actor mentions in a Sidecar are intentionally narrower than the Realm
    // roster: only controller-owned Agents may be selected. The controller is
    // already the sender, and unrelated Realm members are outside the private
    // Circle's collaboration boundary.
    let composer_participants = if sidecar_mode {
        sidecar_owned_agents.clone()
    } else {
        participants_for_messages.clone()
    };

    let presence_participants = if sidecar_mode {
        sidecar_presence_participants(&participants, &account_did)
    } else {
        participants.clone()
    };

    let mut participant_dids_for_presence = presence_participants
        .iter()
        .map(|participant| participant.did.clone())
        .filter(|did| !did.trim().is_empty())
        .collect::<Vec<_>>();
    participant_dids_for_presence.sort();
    participant_dids_for_presence.dedup();
    let has_remote_presence = participant_dids_for_presence
        .iter()
        .any(|did| did != &account_did);
    let presence_sync_key = format!(
        "{}|{}",
        selected_realm_id,
        participant_dids_for_presence.join(",")
    );
    let discussion_feed_loading = !visible_channels_empty
        && visible_message_count == 0
        && !token().trim().is_empty()
        && !initial_sync_finished();
    // Connection details must describe observed state, not hard-coded
    // placeholders. A durable `ak:event:*` row is evidence that the message
    // submit completed. Notification fanout is performed server-side after
    // acceptance and the current protocol exposes no Agent delivery receipt,
    // so label those facts explicitly instead of claiming "Not started" or
    // "Not received".
    let sidecar_delivery_diagnostics = sidecar_session.as_ref().map(|session| {
        let latest = visible_messages
            .iter()
            .filter(|message| {
                message.sender == account_did
                    && message
                        .created_at
                        .is_none_or(|created_at| created_at >= session.opened_at)
            })
            .max_by_key(|message| message.created_at);
        let (submit, fanout, receipt) = match latest {
            Some(message) if message.failed => ("Failed", "Not queued", "Not reported"),
            Some(message) if message.pending => ("Submitting", "Not queued", "Not reported"),
            Some(message) if message.id.starts_with("ak:event:") => {
                ("Accepted", "Server-managed", "Not reported")
            }
            Some(_) => ("Accepted locally", "Pending acceptance", "Not reported"),
            None => ("Not started", "Not started", "Not reported"),
        };
        let last_updated = latest
            .and_then(|message| message.created_at)
            .unwrap_or(session.opened_at)
            .format("%H:%M:%S")
            .to_string();
        (submit, fanout, receipt, last_updated)
    });
    rsx! {
        div {
            class: "{shell_class}",
            "data-testid": "chat-panel",
            "data-chat-mode": if direct_mode { "direct" } else { "collaboration" },
            "data-moderation-appeal-count": "{visible_moderation_appeal_prompt_count}",
            ChatEffects {
                controller,
                account_did: account_did.clone(),
                device_id: device_id.clone(),
                selected_realm_id: selected_realm_id.clone(),
                initial_strand_id: initial_strand_id.clone(),
                plaintext_service_id: plaintext_service_id.clone(),
                sync_cursor,
                realm_live_epoch,
                frontier_state,
                agent_participation_sync_key: agent_participation_sync_key.clone(),
                selected_scope_circle: selected_scope_circle.clone(),
                readable_participation_agent_ids: readable_participation_agent_ids.clone(),
                participant_dids_for_presence: participant_dids_for_presence.clone(),
                account_display_label: account_display_label.clone(),
                has_remote_presence,
                presence_sync_key: presence_sync_key.clone(),
                token,
            }
            if left_open {
                aside { class: "discussion-panel discussion-sidebar-panel", "data-testid": "discussion-list-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {crate::i18n::tr("chat.discussions_header")} }
                            HelpTip { text: "Discussion is the selected Strand's track. The default Strand is always available for this Realm; the alternate filter includes every Strand with a discussion track." }
                        }
                        div { class: "discussion-panel-head-actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                class: "icon-button",
                                "aria-label": crate::i18n::tr("chat.new_strand"),
                                title: crate::i18n::tr("chat.new_strand"),
                                "data-testid": "open-channel-dialog",
                                onclick: move |_| create_dialog_open.set(true),
                                UiIcon { name: "plus" }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: "icon-button",
                                "aria-label": crate::i18n::tr("chat.hide_list"),
                                "data-testid": "collapse-discussion-list",
                                onclick: move |_| left_panel_open.set(false),
                                UiIcon { name: "panel-left-close" }
                            }
                        }
                    }
                    div { class: "discussion-filter segmented-control",
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: if track_filter() == "discussion_only" { "segment active" } else { "segment" },
                            "data-testid": "discussion-filter-only",
                            onclick: move |_| track_filter.set("discussion_only".to_owned()),
                            "Default + discussion"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: if track_filter() == "with_discussion_track" { "segment active" } else { "segment" },
                            "data-testid": "discussion-filter-track",
                            onclick: move |_| track_filter.set("with_discussion_track".to_owned()),
                            "All Strand tracks"
                        }
                    }
                    div { class: "discussion-list", "data-testid": "channel-list",
                        for channel in visible_channels {
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: if channel.strand_id == selected_channel() { "discussion-track-row active" } else { "discussion-track-row" },
                                "data-testid": "channel-item",
                                onclick: {
                                    let id = channel.strand_id.clone();
                                    move |_| controller.select_channel(id.clone())
                                },
                                div { class: "discussion-track-main",
                                    span { class: "discussion-track-name-row",
                                        SecurityStateBadge {
                                            encrypted: channel.security_encrypted.unwrap_or(selected_realm_security_encrypted),
                                            compact: true,
                                            test_id: Some("strand-track-security-state".to_owned()),
                                        }
                                        span { class: "discussion-track-name", "{channel.name}" }
                                    }
                                    span { class: "discussion-track-topic",
                                        if let Some(topic) = &channel.topic {
                                            "{topic}"
                                        } else {
                                            "No topic"
                                        }
                                    }
                                }
                                div { class: "discussion-track-meta",
                                    span { class: "badge", "{channel.category}" }
                                    if channel.unread > 0 {
                                        span { class: "badge accent", "{channel.unread}" }
                                    }
                                }
                            }
                        }
                        if visible_channels_empty {
                            div { class: "discussion-empty", "data-testid": "empty-discussion-list", {crate::i18n::tr("chat.empty_discussions")} }
                        }
                    }
                }
            } else if !embedded && !direct_mode {
                div { class: "discussion-rail discussion-left-rail", "data-testid": "discussion-list-rail",
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "icon-button",
                        "aria-label": "Show discussion list",
                        "data-testid": "expand-discussion-list",
                        onclick: move |_| left_panel_open.set(true),
                        UiIcon { name: "panel-left-open" }
                    }
                }
            }

            if !embedded && !direct_mode && create_dialog_open() {
                Dialog {
                    open: true,
                    on_open_change: move |open: bool| {
                        if !open {
                            create_dialog_open.set(false);
                        }
                    },
                    "data-testid": "channel-create-modal",
                    "aria-label": "New Strand",
                    div { class: "discussion-modal",
                        div { class: "discussion-modal-head",
                            div { class: "discussion-title-row",
                                h2 { "New Strand" }
                                HelpTip { text: "Creates an additional Strand. Its discussion track is available from this view; enable the card option when the same Strand should also carry a synthesis track." }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: "icon-button",
                                "aria-label": "Close",
                                "data-testid": "close-channel-dialog",
                                onclick: move |_| create_dialog_open.set(false),
                                UiIcon { name: "x" }
                            }
                        }
                        div { class: "discussion-modal-body workflow-form",
                            Label { html_for: "new-channel-name-input", {crate::i18n::tr("chat.label.title")} }
                            Input {
                                id: "new-channel-name-input",
                                "data-testid": "new-channel-name",
                                value: "{new_channel_name}",
                                placeholder: "Strand title",
                                oninput: move |event: FormEvent| new_channel_name.set(event.value()),
                            }
                            Label { html_for: "new-channel-topic-input", {crate::i18n::tr("chat.label.summary")} }
                            Input {
                                id: "new-channel-topic-input",
                                "data-testid": "new-channel-topic",
                                value: "{new_channel_topic}",
                                placeholder: "Short purpose or context",
                                oninput: move |event: FormEvent| new_channel_topic.set(event.value()),
                            }
                            CircleScopePicker {
                                selected: new_channel_scope(),
                                circles: eligible_circle_scopes(),
                                test_id: Some("new-channel-circle-scope".to_owned()),
                                onchange: move |scope| new_channel_scope.set(scope),
                            }
                            label { class: "discussion-checkbox-row",
                                Checkbox {
                                    "data-testid": "new-channel-create-card",
                                    checked: if new_channel_create_card() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                    on_checked_change: move |state: CheckboxState| new_channel_create_card.set(bool::from(state)),
                                }
                                span { "Create matching Card" }
                            }
                        }
                        div { class: "discussion-modal-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "cancel-channel-create",
                                onclick: move |_| create_dialog_open.set(false),
                                {crate::i18n::tr("common.cancel")}
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "create-channel-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let realm = selected_realm_id.clone();
                                    move |_| {
                                        let title = new_channel_name().trim().to_owned();
                                        if title.is_empty() {
                                            status_msg.set("Strand title is required".to_owned());
                                            return;
                                        }
                                        let category = "general".to_owned();
                                        let summary = new_channel_topic().trim().to_owned();
                                        let create_card = new_channel_create_card();
                                        let selected_scope_circle = match new_channel_scope() {
                                            CircleScope::Realm => None,
                                            CircleScope::Circle {
                                                circle_id,
                                                title,
                                                member_count,
                                            } => Some(StrandScopeCircle {
                                                circle_id,
                                                title,
                                                member_count,
                                            }),
                                        };
                                        let selected_scope_circle_id = selected_scope_circle
                                            .as_ref()
                                            .map(|scope| scope.circle_id.clone());
                                        let strand_id = format!("ak:strand:{}", uuid_v7());
                                        let rank = format!("r{}", chrono::Utc::now().timestamp_millis());
                                        let op = match ak_ops::discussion_strand_create(
                                            &realm,
                                            &actor,
                                            &strand_id,
                                            &title,
                                        ) {
                                            Ok(builder) => {
                                                let mut op = match builder.build_sdk_event("inkson") {
                                                    Ok(event) => event,
                                                    Err(error) => {
                                                        status_msg.set(format!(
                                                            "Could not create Strand proof: {error}"
                                                        ));
                                                        return;
                                                    }
                                                };
                                                let Some(object) = op
                                                    .payload
                                                    .get_mut("object")
                                                    .and_then(Value::as_object_mut)
                                                else {
                                                    status_msg.set("Could not create Strand: payload object missing".to_owned());
                                                    return;
                                                };
                                                if !object
                                                    .get("fields")
                                                    .is_some_and(Value::is_object)
                                                {
                                                    object.insert("fields".to_owned(), json!({}));
                                                }
                                                let Some(fields) = object
                                                    .get_mut("fields")
                                                    .and_then(Value::as_object_mut)
                                                else {
                                                    status_msg.set("Could not create Strand: fields is not an object".to_owned());
                                                    return;
                                                };
                                                fields.insert("category".to_owned(), json!(category.clone()));
                                                fields.insert("has_synthesis".to_owned(), json!(create_card));
                                                object.insert("rank".to_owned(), json!(rank.clone()));
                                                if !summary.is_empty() {
                                                    object.insert("summary".to_owned(), json!(summary.clone()));
                                                }
                                                if let Some(circle_id) = selected_scope_circle_id.as_deref() {
                                                    object.insert("scope_circle_id".to_owned(), json!(circle_id));
                                                }
                                                if !create_card
                                                    && let Some(tracks) = object
                                                        .get_mut("tracks")
                                                        .and_then(Value::as_object_mut)
                                                {
                                                    tracks.remove("synthesis");
                                                }
                                                op
                                            }
                                            Err(error) => {
                                                status_msg.set(format!(
                                                    "Could not create Strand: {error}"
                                                ));
                                                return;
                                            }
                                        };
                                        let api_token = token();
                                        let wait_for = active_sync_token(sync_cursor());
                                        let channel_topic = if summary.is_empty() { None } else { Some(summary) };
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        status_msg.set("Creating Strand".to_owned());
                                        let sdk_op = op;
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token.clone(), wait_for) {
                                                Ok(api) => match match api.event_submitter() {
                                                        Ok(sub) => sub.submit_sdk_event(&sdk_op).await,
                                                        Err(err) => Err(err),
                                                    }
                                                    {
                                                        Ok(submitted) => {
                                                            channels.write().push(ChannelEntity {
                                                                strand_id: strand_id.clone(),
                                                                name: title.clone(),
                                                                kind: "discussion".to_owned(),
                                                                category: category.clone(),
                                                                topic: channel_topic.clone(),
                                                                unread: 0,
                                                                is_default: false,
                                                                is_private_sidecar: false,
                                                                security_encrypted: None,
                                                                scope_circle: selected_scope_circle.clone(),
                                                            });
                                                            controller.select_channel(strand_id.clone());
                                                            frontier_state.set(submitted.event_id.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                // Keep POST /events sync_token out of the persisted
                                                                // account-subscribe cursor; the background sync loop
                                                                // must resume only from /account/subscribe cursors.
                                                                store.append_raw_operation(
                                                                    sdk_event_local_operation_id(&sdk_op).to_owned(),
                                                                    Some(realm.clone()),
                                                                    json!({
                                                                        "strand_id": strand_id,
                                                                        "kind": "ak.strand.create",
                                                                        "title": title,
                                                                        "category": category,
                                                                        "summary": channel_topic,
                                                                        "create_card": create_card,
                                                                        "object": sdk_op.payload["object"].clone(),
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            status_msg.set("Strand created".to_owned());
                                                            new_channel_name.set(String::new());
                                                            new_channel_topic.set(String::new());
                                                            new_channel_create_card.set(false);
                                                            new_channel_scope.set(CircleScope::Realm);
                                                            create_dialog_open.set(false);
                                                        }
                                                        Err(error) => status_msg.set(format!("Strand create failed: {error}")),
                                                    },
                                                    Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                }
                                            });
                                        }
                                    },
                                {crate::i18n::tr("chat.button.create")}
                            }
                        }
                    }
                }
            }

            section { class: "discussion-panel discussion-main-panel", "data-testid": "discussion-main-panel",
                header { class: "discussion-chat-head",
                    div { class: "discussion-title-stack",
                        div { class: "discussion-title-row",
                            if let Some(security_label) = sidecar_security_label {
                                span {
                                    class: if security_label == "E2EE" { "badge success" } else if security_label == "Private but not E2EE" { "badge warning" } else { "badge amber" },
                                    "data-testid": "sidecar-security-state",
                                    "{security_label}"
                                }
                            } else {
                                SecurityStateBadge {
                                    encrypted: selected_channel_security_encrypted,
                                    compact: true,
                                    test_id: Some("selected-strand-security-state".to_owned()),
                                }
                            }
                            if sidecar_mode { UiIcon { name: "bot" } }
                            h1 { "{selected_channel_name}" }
                        }
                        if sidecar_mode {
                            span { class: "muted sidecar-subtitle", "Private AI sidecar · you and eligible personal agents in this Realm" }
                        }
                    }
                    if !embedded {
                    div { class: "discussion-head-actions",
                        // Start a realm-scoped call. `direct_mode` strands map
                        // to a 1:1 call; group strands open an SFU conference.
                        {
                            let realm_for_call = selected_realm_id.clone();
                            let realm_for_video = selected_realm_id.clone();
                            let call_disabled = realm_for_call.trim().is_empty();
                            rsx! {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    size: ButtonSize::IconSm,
                                    class: "icon-button",
                                    r#type: "button",
                                    "data-testid": "chat-call-voice-button",
                                    "aria-label": crate::i18n::tr("chat.call.voice"),
                                    disabled: call_disabled,
                                    title: crate::i18n::tr("chat.call.voice"),
                                    onclick: move |_| {
                                        navigator.push(Route::Call {
                                            call_id: String::new(),
                                            peer: String::new(),
                                            realm_id: realm_for_call.clone(),
                                            video: "0".to_owned(),
                                            incoming: "0".to_owned(),
                                        });
                                    },
                                    UiIcon { name: "phone" }
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    size: ButtonSize::IconSm,
                                    class: "icon-button",
                                    r#type: "button",
                                    "data-testid": "chat-call-video-button",
                                    "aria-label": crate::i18n::tr("chat.call.video"),
                                    disabled: call_disabled,
                                    title: crate::i18n::tr("chat.call.video"),
                                    onclick: move |_| {
                                        navigator.push(Route::Call {
                                            call_id: String::new(),
                                            peer: String::new(),
                                            realm_id: realm_for_video.clone(),
                                            video: "1".to_owned(),
                                            incoming: "0".to_owned(),
                                        });
                                    },
                                    UiIcon { name: "video" }
                                }
                            }
                        }
                        // T7.2: watch-level fast switcher. Issues a
                        // `ak.strand.watch.set` event on selection. We
                        // optimistically update the local signal first;
                        // a network failure rolls back via status_msg.
                        {
                            let level_now = strand_watch_level();
                            let menu_open = watch_level_menu_open();
                            let level_label = crate::i18n::tr(watch_level_label_key(level_now));
                            let strand_id_for_watch = selected_channel_value.clone();
                            let realm_for_watch = selected_realm_id.clone();
                            let actor_for_watch = account_did.clone();
                            let watch_disabled = strand_id_for_watch.trim().is_empty()
                                || !sidecar_privacy_gate.allows_strand(
                                    crate::sidecar::SidecarDisclosureSurface::Watch,
                                    &strand_id_for_watch,
                                );
                            rsx! {
                                div { class: "watch-level-picker", "data-testid": "watch-level-picker",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        class: "watch-level-toggle",
                                        "data-testid": "watch-level-toggle",
                                        disabled: watch_disabled,
                                        title: crate::i18n::tr("chat.watch_level.tooltip"),
                                        onclick: move |_| {
                                            watch_level_menu_open.set(!watch_level_menu_open());
                                        },
                                        span { class: "watch-level-toggle-label",
                                            "{crate::i18n::tr(\"chat.watch_level.prefix\")}: {level_label}"
                                        }
                                        span { class: "watch-level-toggle-caret", "\u{25be}" }
                                    }
                                    if menu_open && !watch_disabled {
                                        div { class: "watch-level-menu", "data-testid": "watch-level-menu",
                                            {
                                                let options = [
                                                    WatchLevel::MentionsOnly,
                                                    WatchLevel::Participating,
                                                    WatchLevel::All,
                                                    WatchLevel::Muted,
                                                ];
                                                rsx! {
                                                    for option in options.iter().copied() {
                                                        {
                                                            let option_label = crate::i18n::tr(watch_level_label_key(option));
                                                            let strand_id_for_click = strand_id_for_watch.clone();
                                                            let realm_for_click = realm_for_watch.clone();
                                                            let actor_for_click = actor_for_watch.clone();
                                                            let base_for_click = base_url.clone();
                                                            let is_active = level_now == option;
                                                            rsx! {
                                                                Button {
                                                                    variant: ButtonVariant::Secondary,
                                                                    r#type: "button",
                                                                    class: if is_active { "watch-level-option active" } else { "watch-level-option" },
                                                                    "data-testid": "watch-level-option",
                                                                    onclick: move |_| {
                                                                        let prev = strand_watch_level();
                                                                        strand_watch_level.set(option);
                                                                        watch_level_menu_open.set(false);
                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.pending"));
                                                                        let api_token = token();
                                                                        let wait_for = active_sync_token(sync_cursor());
                                                                        let watch_op = match ak_ops::strand_watch_set(
                                                                            &realm_for_click,
                                                                            &actor_for_click,
                                                                            &actor_for_click,
                                                                            &strand_id_for_click,
                                                                            Some(watch_level_wire_value(option)),
                                                                            None,
                                                                        ) {
                                                                            Ok(builder) => builder.build_sdk_event("inkson"),
                                                                            Err(err) => {
                                                                                tracing::warn!("strand_watch_set build failed: {err:#}");
                                                                                strand_watch_level.set(prev);
                                                                                status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let watch_op = match watch_op {
                                                                            Ok(watch_op) => watch_op,
                                                                            Err(err) => {
                                                                                tracing::warn!("strand_watch_set SDK conversion failed: {err:#}");
                                                                                strand_watch_level.set(prev);
                                                                                status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let base = base_for_click.clone();
                                                                        spawn(async move {
                                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                                Ok(api) => match match api.event_submitter() {
                                                                                        Ok(sub) => sub.submit_sdk_event(&watch_op).await,
                                                                                        Err(err) => Err(err),
                                                                                    } {
                                                                                    Ok(_) => {
                                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.saved"));
                                                                                    }
                                                                                    Err(_) => {
                                                                                        // Rollback on failure.
                                                                                        strand_watch_level.set(prev);
                                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                    }
                                                                                },
                                                                                Err(_) => {
                                                                                    strand_watch_level.set(prev);
                                                                                    status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                }
                                                                            }
                                                                        });
                                                                    },
                                                                    "{option_label}"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: if active_right_panel == Some(DiscussionSidePanel::Settings) { "icon-button active" } else { "icon-button" },
                            "aria-label": if sidecar_mode { "Connection details" } else { "Settings" },
                            title: if sidecar_mode { "Connection details" } else { "Settings" },
                            "data-testid": "discussion-settings-toggle",
                            onclick: move |_| {
                                let next_panel = if right_panel() == Some(DiscussionSidePanel::Settings) {
                                    None
                                } else {
                                    Some(DiscussionSidePanel::Settings)
                                };
                                right_panel.set(next_panel);
                            },
                            UiIcon { name: "settings" }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: if active_right_panel == Some(DiscussionSidePanel::Users) { "icon-button active" } else { "icon-button" },
                            "aria-label": if sidecar_mode { "Access" } else { "Users" },
                            title: if sidecar_mode { "Access" } else { "Users" },
                            "data-testid": "discussion-users-toggle",
                            onclick: move |_| {
                                let next_panel = if right_panel() == Some(DiscussionSidePanel::Users) {
                                    None
                                } else {
                                    Some(DiscussionSidePanel::Users)
                                };
                                right_panel.set(next_panel);
                            },
                            UiIcon { name: "users" }
                        }
                    }
                    }
                }

                if let Some(session) = sidecar_session.as_ref() {
                    if !embedded {
                        crate::sidecar::HostedSidecarContextBar {
                            base_url: base_url.clone(),
                            api_token: token(),
                            device_id: device_id.clone(),
                        }
                    }
                    if !session.migrated_draft.trim().is_empty() {
                        div { class: "event info sidecar-draft-notice", "data-testid": "sidecar-draft-migrated", role: "status",
                            strong { "Message moved to this private composer" }
                            span { "It has not been sent. Review it before sending." }
                        }
                    }
                    if let Some(reason) = sidecar_send_block_reason.as_ref() {
                        div { class: "event warning-banner", "data-testid": "sidecar-readiness-gate", role: "alert",
                            strong { {sidecar_security_label.unwrap_or("Not ready")} }
                            span { "{reason}" }
                        }
                    }
                    if let Some(publish_body) = latest_sidecar_publish_body.as_ref() {
                        div { class: "event info sidecar-publish-action",
                            strong { "Publish is explicit" }
                            span { "Copy the latest private result into a normal shared message only after reviewing and confirming its final text." }
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                "data-testid": "sidecar-publish-open",
                                disabled: sidecar_publish_pending(),
                                onclick: {
                                    let publish_body = publish_body.clone();
                                    move |_| {
                                        sidecar_publish_draft.set(publish_body.clone());
                                        sidecar_publish_open.set(true);
                                    }
                                },
                                "Review shared publish"
                            }
                        }
                    }
                }

                // Offline queue banner. Visible while the browser is offline or
                // Garth still has pending chat events for this actor.
                {
                    let queued_count = queued_outbound_message_ids().len();
                    let online = is_online();
                    rsx! {
                        if !online || queued_count > 0 {
                            div {
                                class: "chat-outbox-banner",
                                "data-testid": "chat-outbox-banner",
                                "data-online": if online { "true" } else { "false" },
                                "data-queued-count": "{queued_count}",
                                role: "status",
                                span { class: "chat-outbox-icon", "\u{23f8}" }
                                span {
                                    if online {
                                        {crate::i18n::tr("chat.outbox.flushing")}
                                    } else {
                                        {crate::i18n::tr("chat.outbox.offline_banner")}
                                    }
                                }
                                span {
                                    class: "chat-outbox-count",
                                    "data-testid": "chat-outbox-count",
                                    "{queued_count}"
                                }
                            }
                        }
                    }
                }

                // Shared pin bar. Source is the `ak.pin.*` shared event
                // projection only; holder-private `ak.saved.v1:*`
                // account-data is rendered on message rows instead.
                {
                    let shared_pins_now = shared_pins();
                    let pinned_view: Vec<(String, String, String)> = shared_pins_now
                        .iter()
                        .filter_map(|pin| {
                            messages_for_reply_lookup
                                .iter()
                                .find(|m| {
                                    m.pin_saved_target_ref() == pin.target_ref
                                        || m.id == pin.target_ref
                                })
                                .map(|m| (m.id.clone(), pin.target_ref.clone(), m.body.clone()))
                        })
                        .collect();
                    rsx! {
                        if !pinned_view.is_empty() {
                            div {
                                class: "pinned-bar",
                                "data-testid": "pinned-bar",
                                "data-source": "shared-event",
                                "data-permission": "ak.pin.add ak.pin.remove",
                                div { class: "pinned-bar-head",
                                    UiIcon { name: "pin" }
                                    span { {crate::i18n::tr("pinned_bar.title")} }
                                }
                                div { class: "pinned-bar-list",
                                    for (id, target_ref, body) in pinned_view {
                                        {
                                            let id_for_click = id.clone();
                                            let preview = if body.chars().count() > 40 {
                                                format!(
                                                    "{}...",
                                                    body.chars().take(40).collect::<String>()
                                                )
                                            } else {
                                                body
                                            };
                                            rsx! {
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        r#type: "button",
                                                        class: "pinned-bar-item",
                                                        "data-testid": "pinned-bar-item",
                                                        "data-source": "shared-event",
                                                        "data-target-ref": "{target_ref}",
                                                        title: crate::i18n::tr("pinned_bar.scroll_to"),
                                                        onclick: move |_| {
                                                            // Best-effort scroll: emit
                                                            // a console hint via
                                                            // status_msg so QA can see
                                                            // the click registered.
                                                            // Real scroll-into-view
                                                            // wires into Dioxus's
                                                            // mounted ref API; deferred
                                                            // until A6.3 lands the
                                                            // soland projection.
                                                            status_msg.set(format!(
                                                                "jump to pinned message {}",
                                                                id_for_click
                                                            ));
                                                        },
                                                        UiIcon { name: "pin" }
                                                        span { class: "pinned-bar-preview", "{preview}" }
                                                    }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if selected_realm_pending_mls_binding && selected_channel_security_encrypted {
                    div {
                        class: "event warning-banner",
                        "data-testid": "epoch-update-required-banner",
                        role: "alert",
                        {selected_realm_pending_mls_binding_reason.as_deref().unwrap_or("epoch_update_required")}
                    }
                }

                // G3.Y2 — typing indicator. Shown when one or more
                // other actors in the active strand have sent a
                // `ak.typing` ephemeral within `TYPING_TTL_SECONDS`.
                // The DIDs live on `data-typing-actors` so cotest can
                // assert on them without scraping localised text.
                {
                    let active_typers: Vec<String> = typing_actors()
                        .into_iter()
                        .filter(|did| did != &account_did)
                        .collect();
                    if !active_typers.is_empty() {
                        let attr_value = active_typers.join(",");
                        let live_labels = presence_labels();
                        let label = active_typers
                            .iter()
                            .map(|did| {
                                display_label_for_actor(
                                    &state_store.read(),
                                    &participants_for_messages,
                                    &live_labels,
                                    did,
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        rsx! {
                            div {
                                class: "typing-indicator",
                                "data-testid": "typing-indicator",
                                "data-typing-actors": "{attr_value}",
                                span { class: "typing-dots", "\u{2022}\u{2022}\u{2022}" }
                                span { class: "typing-actors", "{label}" }
                                span { class: "muted", " is typing\u{2026}" }
                            }
                        }
                    } else {
                        rsx! {}
                    }
                }

                ChatTimeline {
                    key: "{_timeline_projection_key}",
                    controller,
                    context: ChatTimelineContext {
                        embedded,
                        visible_messages: visible_messages.clone(),
                        visible_moderation_appeal_prompts: visible_moderation_appeal_prompts.clone(),
                        strand_scope_lookup: strand_scope_lookup.clone(),
                        private_sidecar_strand_ids: private_sidecar_strand_ids.clone(),
                        account_did: account_did.clone(),
                        account_display_label: account_display_label.clone(),
                        participants: participants_for_messages.clone(),
                        selected_realm_id: selected_realm_id.clone(),
                        selected_channel_id: sidecar_session
                            .as_ref()
                            .map(|session| session.private_strand_id.clone())
                            .unwrap_or_else(|| selected_channel_value.clone()),
                        sidecar_active: sidecar_mode,
                        device_id: device_id.clone(),
                        plaintext_service_id: plaintext_service_id.clone(),
                        base_url: base_url.clone(),
                        focus_message_id: focus_message_id.clone(),
                        blocked_dids: blocked_did_set.clone(),
                        selected_channel_security_encrypted,
                        visible_channels_empty,
                        visible_message_count,
                        loading: discussion_feed_loading,
                        token,
                        sync_cursor,
                        frontier_state,
                    }
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Users) {
                aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-users-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {if sidecar_mode { "Access".to_owned() } else { crate::i18n::tr("chat.users_header") }} }
                        }
                    }
                    // T7.5: lightweight tab bar so members and settings
                    // share a single right panel rather than competing
                    // for the same slot. Each tab maps to one
                    // `DiscussionSidePanel` value the existing buttons
                    // already toggle.
                    div { class: "discussion-right-tabs",
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "discussion-right-tab active",
                            "data-testid": "discussion-right-tab-members",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Users)),
                            {if sidecar_mode { "Access".to_owned() } else { crate::i18n::tr("chat.tabs.members") }}
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "discussion-right-tab",
                            "data-testid": "discussion-right-tab-settings",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Settings)),
                            {if sidecar_mode { "Connection details".to_owned() } else { crate::i18n::tr("chat.tabs.settings") }}
                        }
                    }
                    if let Some(session) = sidecar_session.as_ref() {
                        div { class: "discussion-detail-section sidecar-access-section", "data-testid": "sidecar-access-panel",
                            div { class: "discussion-subhead", span { "Sidecar members" } }
                            div { class: "sidecar-access-row",
                                div {
                                    strong {
                                        if account_primary_handle.trim().is_empty() {
                                            "You"
                                        } else {
                                            "{account_primary_handle}"
                                        }
                                    }
                                    span { class: "muted", "Controller" }
                                }
                                span { class: "badge success", "Active" }
                            }
                            for agent in &sidecar_owned_agents {
                                {
                                    let agent_id = agent.did.clone();
                                    let slug = agent.agent_metadata.as_ref()
                                        .map(|metadata| metadata.agent_slug.trim().to_owned())
                                        .filter(|slug| !slug.is_empty())
                                        .unwrap_or_else(|| short_principal_label(&agent_id));
                                    let selector = agent_selector_label(agent);
                                    let addressed_now = session.addressed_agent_ids.iter()
                                        .any(|candidate| candidate == &agent_id);
                                    rsx! {
                                        div { class: "sidecar-access-row", key: "{agent_id}", "data-testid": "sidecar-agent-row",
                                            div {
                                                strong { "{slug}" }
                                                if let Some(selector) = selector {
                                                    span { class: "muted", "@{selector}" }
                                                }
                                                span { class: "muted mono", "{agent_id}" }
                                            }
                                            span { class: if addressed_now { "badge accent" } else { "badge" },
                                                if addressed_now { "Addressed now" } else { "Eligible agent" }
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "event info",
                                "Sidecar access is derived from your eligible personal Agents. The badge marks the Agent addressed by the current message."
                            }
                            div { class: "discussion-subhead", span { "Encryption" } }
                            div { class: "detail-row", span { "Profile" } strong { {sidecar_security_label.unwrap_or("Opening")} } }
                            div { class: "detail-row", span { "Membership reconciliation" } strong {
                                if session.membership_ready() { "Complete" } else { "Pending" }
                            } }
                            div { class: "detail-row", span { "Pending members" } strong { "{session.pending_reconciliation_count()}" } }
                        }
                    }
                    // G3.Y2 — presence list. One row per participant
                    // with `data-presence-state` derived from soland's
                    // live profile presence surface.
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Presence" } }
                        div {
                            class: "presence-list",
                            "data-testid": "presence-list",
                            for participant in &presence_participants {
                                {
                                    let did_attr = participant.did.clone();
                                    let live_labels = presence_labels();
                                    let display = display_label_for_actor(
                                        &state_store.read(),
                                        &participants,
                                        &live_labels,
                                        &participant.did,
                                    );
                                    let state = presence_states
                                        .read()
                                        .get(&participant.did)
                                        .cloned()
                                        .unwrap_or_else(|| {
                                            if participant.is_self {
                                                "online".to_owned()
                                            } else {
                                                "offline".to_owned()
                                            }
                                        });
                                    let state_for_class = state.clone();
                                    let status_message = presence_status_messages
                                        .read()
                                        .get(&participant.did)
                                        .cloned();
                                    rsx! {
                                        div {
                                            class: "presence-row presence-row-{state_for_class}",
                                            "data-testid": "presence-row",
                                            "data-actor-did": "{did_attr}",
                                            "data-presence-state": "{state}",
                                            span { class: "presence-dot presence-dot-{state}" }
                                            span { class: "presence-name", title: "{did_attr}",
                                                "{display}"
                                                if participant.is_self {
                                                    SelfAttributionBadge {
                                                        class: Some("participant-inline-self-badge".to_owned()),
                                                        test_id: Some("presence-self-badge".to_owned()),
                                                    }
                                                }
                                            }
                                            span { class: "muted", " ({state})" }
                                            if let Some(status_message) = status_message {
                                                span {
                                                    class: "muted presence-status-message",
                                                    "data-testid": "presence-status-message",
                                                    " — {status_message}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Space users" } }
                        for row in participant_roster_rows(&participants, &public_agent_dids) {
                            {
                                match row {
                                    ParticipantRosterRow::Participant(participant) => {
                                        let display_label = participant_roster_display_label(
                                            &state_store.read(),
                                            &participant,
                                        );
                                        rsx! {
                                            DiscussionParticipantRow {
                                                participant,
                                                participants: participants_for_messages.clone(),
                                                display_label,
                                                nested_agent: false,
                                                show_binding_details: true,
                                            }
                                        }
                                    }
                                    ParticipantRosterRow::ControllerWithAgents { controller, agents } => {
                                        let controller_id = controller.did.clone();
                                        let agent_count = agents.len();
                                        let display_label = participant_roster_display_label(
                                            &state_store.read(),
                                            &controller,
                                        );
                                        let agent_count_label = if agent_count == 1 {
                                            "1 agent".to_owned()
                                        } else {
                                            format!("{agent_count} agents")
                                        };
                                        let group_aria_label = format!(
                                            "Show {agent_count_label} for {display_label}"
                                        );
                                        rsx! {
                                            details {
                                                class: "participant-agent-group",
                                                "data-testid": "participant-agent-group",
                                                "data-controller-id": "{controller_id}",
                                                summary {
                                                    class: "participant-agent-group-summary",
                                                    "aria-label": "{group_aria_label}",
                                                    DiscussionParticipantRow {
                                                        participant: controller,
                                                        participants: participants_for_messages.clone(),
                                                        display_label,
                                                        nested_agent: false,
                                                        show_binding_details: false,
                                                    }
                                                    span {
                                                        class: "participant-agent-group-toggle muted",
                                                        "data-testid": "participant-agent-group-toggle",
                                                        "{agent_count_label}"
                                                    }
                                                }
                                                div { class: "participant-agent-children",
                                                    for agent in agents {
                                                        {
                                                            let display_label = participant_roster_display_label(
                                                                &state_store.read(),
                                                                &agent,
                                                            );
                                                            rsx! {
                                                                DiscussionParticipantRow {
                                                                    participant: agent,
                                                                    participants: participants_for_messages.clone(),
                                                                    display_label,
                                                                    nested_agent: true,
                                                                    show_binding_details: true,
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Settings) {
                {
                // F-CHAT-DEAD-UI-1: three toggles in the discussion-settings
                // panel used to be pure decoration (no onchange, hard-coded
                // `checked: true`). The first two are now wired to the
                // same actor-private account_data that /settings already
                // edits, so a change here mirrors immediately into the
                // global view. "Shared history" is a Realm-scoped policy
                // event (`ak.realm.history_visibility`) — it's not a
                // client-`ak.realm.history_visibilityso the third row
                // shows an explanatory hint instead of pretending to be
                // a checkbox.
                let realm_id_for_mute = selected_realm_id.clone();
                let strand_id_for_rr = selected_channel_value.clone();
                let muted_realms_now = state_store.read().muted_realms();
                let realm_is_muted = muted_realms_now.contains(&realm_id_for_mute);
                let rr_default_send = state_store.read().read_receipt_default_send();
                let rr_strand_override =
                    state_store.read().read_receipt_strand_override(&strand_id_for_rr);
                let rr_active = rr_strand_override.unwrap_or(rr_default_send);
                let rr_default_display = state_store.read().read_receipt_default_display();
                let rr_strand_display_override = state_store
                    .read()
                    .read_receipt_strand_display_override(&strand_id_for_rr);
                let rr_display_active = rr_strand_display_override.unwrap_or(rr_default_display);
                rsx! {
                aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-settings-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {if sidecar_mode { "Connection details".to_owned() } else { crate::i18n::tr("chat.settings_header") }} }
                        }
                    }
                    // T7.5: same tab bar as the users panel so the user
                    // can switch tabs in-place without re-clicking the
                    // topbar icons.
                    div { class: "discussion-right-tabs",
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "discussion-right-tab",
                            "data-testid": "discussion-right-tab-members",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Users)),
                            {if sidecar_mode { "Access".to_owned() } else { crate::i18n::tr("chat.tabs.members") }}
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "discussion-right-tab active",
                            "data-testid": "discussion-right-tab-settings",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Settings)),
                            {if sidecar_mode { "Connection details".to_owned() } else { crate::i18n::tr("chat.tabs.settings") }}
                        }
                    }
                    if let (Some(session), Some((submit, fanout, receipt, last_updated))) =
                        (sidecar_session.as_ref(), sidecar_delivery_diagnostics.as_ref())
                    {
                        div { class: "discussion-detail-section sidecar-diagnostics-section", "data-testid": "sidecar-connection-details",
                            div { class: "detail-row", span { "Trace ID" } strong { class: "mono", "{session.trace_id}" } }
                            div { class: "detail-row", span { "Ensure" } strong { "Complete" } }
                            div { class: "detail-row", span { "Private access" } strong {
                                if session.membership_ready() { "Complete" } else { "Reconciling" }
                            } }
                            div { class: "detail-row", span { "Encryption" } strong { {sidecar_security_label.unwrap_or("Opening")} } }
                            div { class: "detail-row", span { "Message submit" } strong { "{submit}" } }
                            div { class: "detail-row", span { "Notification fanout" } strong { "{fanout}" } }
                            div { class: "detail-row", span { "Agent receipt" } strong { "{receipt}" } }
                            div { class: "detail-row", span { "Last updated" } strong { "{last_updated}" } }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "sidecar-copy-diagnostics",
                                    onclick: {
                                        let summary = session.diagnostic_summary(
                                            sidecar_security_label.unwrap_or("Opening"),
                                            submit,
                                            fanout,
                                            receipt,
                                            last_updated,
                                        );
                                        move |_| yoface::utils::dom::copy_text_to_clipboard(&summary)
                                    },
                                    "Copy diagnostic summary"
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    onclick: move |_| {
                                        navigator.push(Route::SettingsSection {
                                            section: "agents".to_owned(),
                                            filter: String::new(),
                                        });
                                    },
                                    "Open agent settings"
                                }
                            }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Settings" } }
                        label { class: "settings-row",
                            span { {crate::i18n::tr("chat.settings.mute_notifications")} }
                            Checkbox {
                                "data-testid": "discussion-settings-mute",
                                checked: if realm_is_muted { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: {
                                    let realm_id = realm_id_for_mute.clone();
                                    move |state: CheckboxState| {
                                        let new_muted = bool::from(state);
                                        state_store
                                            .write()
                                            .set_realm_muted(realm_id.clone(), new_muted);
                                    }
                                },
                            }
                        }
                        label { class: "settings-row",
                            span { {crate::i18n::tr("chat.settings.read_receipts")} }
                            Checkbox {
                                "data-testid": "discussion-settings-read-receipts",
                                checked: if rr_active { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: {
                                    let strand_id = strand_id_for_rr.clone();
                                    move |state: CheckboxState| {
                                        let new_value = bool::from(state);
                                        state_store
                                            .write()
                                            .set_read_receipt_strand_override(
                                                strand_id.clone(),
                                                Some(new_value),
                                            );
                                    }
                                },
                            }
                        }
                        label { class: "settings-row",
                            span { "Show others' read receipts" }
                            Checkbox {
                                "data-testid": "discussion-settings-read-receipts-display",
                                checked: if rr_display_active { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: {
                                    let strand_id = strand_id_for_rr.clone();
                                    move |state: CheckboxState| {
                                        let new_value = bool::from(state);
                                        state_store
                                            .write()
                                            .set_read_receipt_strand_display_override(
                                                strand_id.clone(),
                                                Some(new_value),
                                            );
                                    }
                                },
                            }
                        }
                        div { class: "settings-row settings-row-readonly",
                            "data-testid": "discussion-settings-shared-history-note",
                            span { {crate::i18n::tr("chat.settings.shared_history")} }
                            span { class: "muted",
                                {crate::i18n::tr("chat.settings.shared_history_hint")}
                            }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Selected" } }
                        div { class: "detail-row", span { "Category" } strong { "{selected_channel_category}" } }
                        div { class: "detail-row", span { "Unread" } strong { "{selected_channel_unread}" } }
                        div { class: "detail-row", span { "Messages" } strong { "{visible_message_count}" } }
                    }
                }
                }
                }
            }

            if sidecar_publish_open() {
                if let Some(session) = sidecar_session.as_ref() {
                    div {
                        class: "discussion-modal-backdrop",
                        "data-testid": "sidecar-publish-modal",
                        div {
                            class: "discussion-modal",
                            role: "dialog",
                            "aria-modal": "true",
                            "aria-labelledby": "sidecar-publish-title",
                            div { class: "discussion-modal-head",
                                h2 { id: "sidecar-publish-title", "Publish to shared Strand" }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    r#type: "button",
                                    "data-testid": "sidecar-publish-cancel",
                                    disabled: sidecar_publish_pending(),
                                    onclick: move |_| {
                                        sidecar_publish_open.set(false);
                                        sidecar_publish_draft.set(String::new());
                                    },
                                    "Cancel"
                                }
                            }
                            div { class: "discussion-modal-body workflow-form",
                                p {
                                    "This creates a normal shared message in the source Strand. Sidecar identifiers, private history, exchange metadata, and locators are never copied."
                                }
                                label { class: "form-row",
                                    span { "Final shared text" }
                                    textarea {
                                        "data-testid": "sidecar-publish-body",
                                        value: "{sidecar_publish_draft}",
                                        disabled: sidecar_publish_pending(),
                                        oninput: move |event| sidecar_publish_draft.set(event.value()),
                                    }
                                }
                            }
                            div { class: "discussion-modal-actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    r#type: "button",
                                    "data-testid": "sidecar-publish-confirm",
                                    disabled: sidecar_publish_pending()
                                        || sidecar_publish_draft().trim().is_empty(),
                                    onclick: {
                                        let base = base_url.clone();
                                        let realm = session.source_realm_id.clone();
                                        let actor = account_did.clone();
                                        let target_strand = session.source_strand_id.clone();
                                        move |_| {
                                            let body = sidecar_publish_draft().trim().to_owned();
                                            let gate = crate::sidecar::SidecarPrivacyGate::from_store(
                                                &state_store.read(),
                                                &actor,
                                            );
                                            let operation =
                                                match confirmed_sidecar_publish_message_operation(
                                                    &gate,
                                                    true,
                                                    &realm,
                                                    &actor,
                                                    &target_strand,
                                                    &new_chat_message_id(),
                                                    &body,
                                                ) {
                                                    Ok(operation) => operation,
                                                    Err(error) => {
                                                        status_msg.set(format!(
                                                            "Shared publish blocked: {error:#}"
                                                        ));
                                                        return;
                                                    }
                                                };
                                            sidecar_publish_pending.set(true);
                                            let credential = token();
                                            let base = base.clone();
                                            spawn(async move {
                                                let result =
                                                    crate::transport::auth::with_authed_api(
                                                        &base,
                                                        credential,
                                                        |api| async move {
                                                            let submitter = api.event_submitter()?;
                                                            let mut attempt = 0_u8;
                                                            loop {
                                                                match submitter
                                                                    .submit_sdk_event(&operation)
                                                                    .await
                                                                {
                                                                    Ok(result) => {
                                                                        break Ok(Some(result));
                                                                    }
                                                                    Err(error)
                                                                        if crate::event_submit::is_durably_queued_error(
                                                                            &error,
                                                                        ) && attempt < 2 =>
                                                                    {
                                                                        attempt += 1;
                                                                        crate::runtime_helpers::sleep_for(
                                                                            std::time::Duration::from_millis(
                                                                                1_100,
                                                                            ),
                                                                        )
                                                                        .await;
                                                                    }
                                                                    Err(error)
                                                                        if crate::event_submit::is_durably_queued_error(
                                                                            &error,
                                                                        ) =>
                                                                    {
                                                                        break Ok(None);
                                                                    }
                                                                    Err(error) => break Err(error),
                                                                }
                                                            }
                                                        },
                                                    )
                                                    .await;
                                                sidecar_publish_pending.set(false);
                                                match result {
                                                    Ok(Some(_)) => {
                                                        sidecar_publish_open.set(false);
                                                        sidecar_publish_draft.set(String::new());
                                                        status_msg.set(
                                                            "Published to shared Strand".to_owned(),
                                                        );
                                                    }
                                                    Ok(None) => {
                                                        sidecar_publish_open.set(false);
                                                        sidecar_publish_draft.set(String::new());
                                                        status_msg.set(
                                                            "Shared publish queued for retry"
                                                                .to_owned(),
                                                        );
                                                    }
                                                    Err(error) => status_msg.set(format!(
                                                        "Shared publish failed: {}",
                                                        error.display()
                                                    )),
                                                }
                                            });
                                        }
                                    },
                                    "Confirm shared publish"
                                }
                            }
                        }
                    }
                }
            }

            // Experimental private-discussion workflow. It remains feature
            // gated until the multi-event operation can resume safely after a
            // partial failure.
            if crate::messaging::discussion_promote::discussion_promote_enabled()
                && promote_discussion_draft.read().is_open()
            {
                div { class: "discussion-modal-backdrop",
                    "data-testid": "discussion-promote-modal",
                    div { class: "discussion-modal",
                        div { class: "discussion-modal-head",
                            h2 { "Create a private Circle discussion" }
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                onclick: move |_| promote_discussion_draft.write().close(),
                                "Cancel"
                            }
                        }
                        label { class: "form-row",
                            span { "Private discussion title" }
                            input {
                                r#type: "text",
                                "data-testid": "discussion-promote-confirm-input",
                                value: "{promote_discussion_draft.read().title}",
                                oninput: move |evt| {
                                    promote_discussion_draft.write().title = evt.value();
                                },
                            }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "discussion-promote-confirm-button",
                                disabled: !promote_discussion_draft.read().is_submittable(),
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    move |_| {
                                        let draft_snapshot = promote_discussion_draft.read().clone();
                                        let Some(source_id) = draft_snapshot.source_id.clone() else {
                                            return;
                                        };
                                        let title = draft_snapshot.title.trim().to_owned();
                                        let ids = crate::messaging::discussion_promote::PromoteIds::fresh();
                                        // Optimistic UI: seal the
                                        // promoted indicator before the
                                        // server round-trip completes.
                                        promoted_targets
                                            .write()
                                            .insert(source_id.clone(), ids.discussion_strand_id.clone());
                                        promote_discussion_draft.write().close();

                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let actor = actor.clone();
                                        let api_token = token();
                                        let ids_clone = ids.clone();
                                        let source_id_for_rollback = source_id.clone();
                                        spawn(async move {
                                            // Experimental discussion promote is
                                            // hidden from the default local UI
                                            // until soland's reducer is enabled.
                                            // YOU-02-007: stop at the first
                                            // failed op and roll back the
                                            // optimistic promoted indicator so
                                            // a half-applied promote is not
                                            // presented as success.
                                            let outcome = crate::transport::auth::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    let ops = crate::messaging::discussion_promote::build_promote_ops(
                                                        &realm,
                                                        &actor,
                                                        &source_id,
                                                        &ids_clone,
                                                        &title,
                                                    )?;
                                                    for op in ops {
                                                        api.event_submitter()?.submit_sdk_event(&op).await?;
                                                    }
                                                    Ok(())
                                                },
                                            ).await;
                                            if let Err(err) = outcome {
                                                tracing::warn!(
                                                    "discussion promote failed: {}",
                                                    err.display()
                                                );
                                                promoted_targets
                                                    .write()
                                                    .remove(&source_id_for_rollback);
                                                status_msg.set(format!(
                                                    "Private discussion creation failed: {}",
                                                    err.display()
                                                ));
                                            }
                                        });
                                    }
                                },
                                "Create private discussion"
                            }
                        }
                    }
                }
            }

            ChatComposer {
                controller,
                context: ChatComposerContext {
                    embedded,
                    selected_channel_info: selected_channel_info.clone(),
                    account_did: account_did.clone(),
                    account_display_label: account_display_label.clone(),
                    participants: composer_participants.clone(),
                    selected_realm_id: selected_realm_id.clone(),
                    device_id: device_id.clone(),
                    plaintext_service_id: plaintext_service_id.clone(),
                    selected_channel_security_encrypted,
                    selected_realm_pending_mls_binding,
                    selected_realm_pending_mls_binding_reason: selected_realm_pending_mls_binding_reason.clone(),
                    active_sidecar_session: sidecar_session.clone(),
                    sidecar_send_block_reason: sidecar_send_block_reason.clone(),
                    public_agent_dids: public_agent_dids.clone(),
                    own_controller_handle: own_controller_handle.clone(),
                    mention_insert_request,
                    mentions_enabled: composer::chat_mentions_enabled(direct_mode),
                    token,
                    sync_cursor,
                    frontier_state,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
