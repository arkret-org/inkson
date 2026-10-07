use arkret_sdk::push_rule_core::WatchLevel;
use arkret_wire::event_kind_str;
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_primitives::dropdown_menu::{
    DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
};
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::circle::{CircleScope, CircleSummary};
use crate::components::{
    ActorIdentityLabel, CircleScopePicker, HelpTip, SecurityStateBadge, SelfAttributionBadge,
    UiIcon,
};
use crate::models::SubmitEventResult;
use crate::operation::{ak_ops, trim_realm_id, uuid_v7};
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
    MentionNode, active_sync_token, parse_mention_nodes, short_protocol_id,
};

pub(crate) mod agent_modes;
mod circle_welcome;
mod composer;
mod controller;
mod direct_authority;
mod direct_structure;
mod effects;
pub(crate) mod model;
mod poll_submission;
mod retained_host;
mod right_panel;
mod scheduled_send_panel;
mod sidecar_projection;
mod sidecar_restore;
mod timeline;
mod timeline_projection;
mod timeline_surface;
mod timeline_window;
pub(crate) use retained_host::RetainedDiscussionHost;

const PRESENCE_HEARTBEAT_SECS: u64 = 25;
const PRESENCE_STARTUP_RETRY_SECS: u64 = 2;

#[inline(always)]
fn trace_private_send_stage(_stage: &'static str) {
    #[cfg(feature = "wasm-localstorage-secrets-test")]
    tracing::warn!(target: "sidecar", stage = _stage, "joint Sidecar preparation stage");
}

fn presence_heartbeat_delay_secs(heartbeat_tick: u64) -> u64 {
    if heartbeat_tick == 0 {
        PRESENCE_STARTUP_RETRY_SECS
    } else {
        PRESENCE_HEARTBEAT_SECS
    }
}

#[derive(serde::Serialize)]
struct AcceptedChatMessageOperation<'a> {
    event_id: &'a str,
    kind: &'static str,
    actor_id: &'a str,
    body: &'a str,
    content: &'a Value,
    strand_id: &'a str,
    message_id: &'a str,
    mentions: &'a [Value],
    reply_to: Option<&'a str>,
    /// Send-queue lifecycle of the submission that produced this row.
    status: &'a garth::SendQueueStatus,
}

fn principal_core_key(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    arkret_sdk::DidCoreId::new(value.to_owned())
        .ok()
        .map(|id| id.as_str().to_owned())
}

fn same_principal_core(left: &str, right: &str) -> bool {
    principal_core_key(left)
        .is_some_and(|left| principal_core_key(right).as_deref() == Some(left.as_str()))
}

fn watch_level_from_wire(value: arkret_sdk::StrandWatchLevel) -> WatchLevel {
    match value {
        arkret_sdk::StrandWatchLevel::MentionsOnly => WatchLevel::MentionsOnly,
        arkret_sdk::StrandWatchLevel::Participating => WatchLevel::Participating,
        arkret_sdk::StrandWatchLevel::All => WatchLevel::All,
        arkret_sdk::StrandWatchLevel::Muted => WatchLevel::Muted,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MentionInsertRequest {
    request_id: String,
    subject_account_id: arkret_sdk::AccountId,
    require_agent_identity: bool,
}

impl MentionInsertRequest {
    pub fn new(subject_account_id: arkret_sdk::AccountId, require_agent_identity: bool) -> Self {
        Self {
            request_id: uuid_v7(),
            subject_account_id,
            require_agent_identity,
        }
    }

    fn resolve_candidate(
        &self,
        participants: &[SpaceParticipant],
        requester_principal_id: &str,
        public_agent_ids: &std::collections::BTreeSet<String>,
    ) -> Option<crate::messaging::mentions::MentionCandidate> {
        let participant = participants.iter().find(|participant| {
            participant
                .actor_id
                .as_ref()
                .and_then(arkret_sdk::ActorId::as_account_id)
                == Some(&self.subject_account_id)
        })?;
        // The card may already know this owned Agent while the chat's current
        // inventory is still loading. Do not consume that selection as an
        // ordinary member mention before its Agent visibility can be checked.
        if self.require_agent_identity && !participant.is_agent {
            return None;
        }
        mention_candidate_for_explicit_target(
            participant,
            participants,
            requester_principal_id,
            public_agent_ids,
            None,
            None,
        )
    }
}

// Re-exported for the sync engine so the account-aggregate stream folds
// discussion message events into the shared `raw_operations` log (local-first
// feed), mirroring `kanban::kanban_operations_from_events`.
use composer::{ChatComposer, ChatComposerContext};
use controller::{
    ChatCommandContext, ChatController, ChatProjectionEvent, ChatProjectionSink, StrandCreateDraft,
    use_chat_controller,
};
use effects::ChatEffects;
#[cfg(test)]
pub(crate) use model::message_operations_from_events;
use model::*;
pub(crate) use model::{
    default_discussion_strand_id, verified_chat_sender_domain_for_realm,
    verify_chat_envelope_proof_for_realm,
};
use right_panel::{DiscussionSettingsPanel, DiscussionUsersPanel, SidecarDeliveryDiagnostics};
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

fn position_local_timeline_rows(messages: Vec<ChatMessage>) -> Vec<ChatMessage> {
    let (mut local, mut accepted): (Vec<_>, Vec<_>) = messages
        .into_iter()
        .partition(|message| message.pending || message.failed);
    // Pending rows have no Commit position. Use their local send time only to
    // place the optimistic display; never reorder accepted history by clocks.
    local.sort_by_key(|message| message.created_at);
    for message in local {
        let index = message.created_at.and_then(|created_at| {
            accepted.iter().position(|candidate| {
                candidate.realm_id == message.realm_id
                    && candidate.strand_id == message.strand_id
                    && candidate.created_at.is_some_and(|at| at > created_at)
            })
        });
        accepted.insert(index.unwrap_or(accepted.len()), message);
    }
    accepted
}

fn project_visible_messages(
    messages: &[ChatMessage],
    selected_channel_id: &str,
    selected_realm_id: &str,
    sidecar_projection: Option<&str>,
    exchange_projections: &[arkret_sdk::AgentSidecarExchangeProjection],
    sidecar_current_available: bool,
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
        let is_private_echo = echo_projection_by_event.contains_key(&message.id);
        if matches!(
            message.local_scope,
            Some(arkret_sdk::ScopeRef::Sidecar { .. })
        ) && (!sidecar_current_available || !is_private_echo)
        {
            continue;
        }
        if !sidecar_current_available {
            // Durable source rows arrive through the independently verified
            // ordinary fold. Only explicitly ordinary-scoped optimistic rows
            // may join them while private history verification is unavailable.
            let ordinary_local_scope = message.local_scope.as_ref().is_some_and(|scope| {
                matches!(scope, arkret_sdk::ScopeRef::Realm { realm_id } | arkret_sdk::ScopeRef::Circle { realm_id, .. } if realm_id.as_str() == selected_realm_id)
            });
            let durable_source_row =
                message.id.starts_with("ak:event:") && !message.pending && !message.failed;
            if is_private_echo
                || (sidecar_projection.is_some() && !ordinary_local_scope && !durable_source_row)
            {
                continue;
            }
        }
        let is_source_echo = sidecar_current_available && is_private_echo;
        let strand_matches = sidecar_projection.map_or_else(
            || message.strand_id == selected_channel_id || is_source_echo,
            |source_strand_id| is_source_echo || message.strand_id == source_strand_id,
        );
        if !strand_matches {
            continue;
        }

        let dedupe_key = message.id.clone();
        if let std::collections::btree_map::Entry::Vacant(e) = positions.entry(dedupe_key) {
            e.insert(visible.len());
            visible.push(message.clone());
        }
    }
    let source_strand_id = sidecar_projection.unwrap_or(selected_channel_id);
    let visible_source_ids = visible
        .iter()
        .filter(|message| message.strand_id == source_strand_id)
        .map(|message| message.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    visible.retain(|message| {
        echo_projection_by_event
            .get(&message.id)
            .is_none_or(|projection| {
                projection
                    .source_event_id
                    .as_ref()
                    .is_none_or(|anchor| visible_source_ids.contains(anchor.as_str()))
            })
    });
    visible =
        timeline_projection::interleave_private_timeline_rows(visible, &echo_projection_by_event);
    visible
}

/// Pending local rows remain visible only with ordinary-composer provenance.
/// Accepted history is rebuilt from verified Events; unscoped Sidecar rows
/// cannot enter the ordinary Realm timeline through a reused Strand ID.
fn verified_scope_timeline_seed(rows: &[ChatMessage]) -> Vec<ChatMessage> {
    rows.iter()
        .filter(|row| {
            (row.pending || row.failed)
                && row.local_scope.as_ref().is_some_and(|scope| {
                    matches!(
                        scope,
                        arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. }
                    ) && scope.realm_id().as_str() == row.realm_id
                })
        })
        .cloned()
        .collect()
}

fn owned_agent_ids_from_composer(
    mentions_enabled: bool,
    mentions: &[MentionNode],
    participants: &[crate::views::chat::model::SpaceParticipant],
    controller_principal_id: &str,
) -> Vec<String> {
    if !mentions_enabled {
        return Vec::new();
    }
    let Some(controller_account) =
        crate::mls_api_helpers::local_account_actor_id(controller_principal_id)
            .ok()
            .and_then(|actor| actor.as_account_id().cloned())
    else {
        return Vec::new();
    };
    // Route only a structured, complete AccountId selected from an actor row
    // that the current controller-owned Agent inventory also names. Historic
    // selector metadata, slug text and a principal-only match are insufficient.
    let mut agent_ids = mentions
        .iter()
        .filter_map(MentionNode::as_mention)
        .filter(|mention| {
            participants.iter().any(|participant| {
                participant.is_agent
                    && mention.subject_account_id.station_id == controller_account.station_id
                    && participant
                        .actor_id
                        .as_ref()
                        .and_then(arkret_sdk::ActorId::as_account_id)
                        == Some(&mention.subject_account_id)
                    && participant.agent_metadata.as_ref().is_some_and(|metadata| {
                        same_principal_core(
                            &metadata.controller_principal_id,
                            controller_principal_id,
                        )
                    })
            })
        })
        .map(|mention| mention.subject_account_id.principal_id.as_str().to_owned())
        .collect::<Vec<_>>();
    agent_ids.sort_unstable();
    agent_ids.dedup();
    agent_ids
}

fn composer_shared_agent_targets(
    scope: arkret_sdk::AgentMentionComposerScope,
    mentions: &[MentionNode],
    participants: &[SpaceParticipant],
    candidates: &[crate::messaging::mentions::MentionCandidate],
) -> Vec<arkret_sdk::AccountId> {
    if matches!(
        scope,
        arkret_sdk::AgentMentionComposerScope::Direct
            | arkret_sdk::AgentMentionComposerScope::Sidecar
    ) {
        return Vec::new();
    }
    mentions
        .iter()
        .filter_map(MentionNode::as_mention)
        .filter(|m| {
            participants.iter().any(|p| {
                p.is_agent && participant_mention_account(p).as_ref() == Some(&m.subject_account_id)
            }) || candidates
                .iter()
                .any(|c| c.is_agent && c.subject_account_id == m.subject_account_id)
        })
        .map(|m| m.subject_account_id.clone())
        .collect()
}

fn composer_agent_mode_route(
    scope: arkret_sdk::AgentMentionComposerScope,
    mentions: &[MentionNode],
    participants: &[SpaceParticipant],
    controller: &arkret_sdk::AccountId,
    candidates: &[crate::messaging::mentions::MentionCandidate],
    modes: &std::collections::BTreeMap<arkret_sdk::AccountId, arkret_sdk::AgentInteractionMode>,
) -> arkret_sdk::AgentMentionRoute {
    let own = Some(controller.clone());
    let mut selected = Vec::new();
    let mut outside = false;
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    let (mut unknown_mode_count, mut unowned_private_count, mut missing_participant_count) =
        (0, 0, 0);
    for mention in mentions.iter().filter_map(MentionNode::as_mention) {
        let target = participants
            .iter()
            .find(|p| participant_mention_account(p).as_ref() == Some(&mention.subject_account_id));
        if target.is_some_and(|p| p.is_agent)
            || candidates
                .iter()
                .any(|c| c.is_agent && c.subject_account_id == mention.subject_account_id)
        {
            let mode = modes.get(&mention.subject_account_id).copied();
            let owned = target
                .and_then(|p| p.agent_metadata.as_ref())
                .is_some_and(|m| {
                    same_principal_core(
                        &m.controller_principal_id,
                        controller.principal_id.as_str(),
                    )
                })
                && own
                    .as_ref()
                    .is_some_and(|a| a.station_id == mention.subject_account_id.station_id);
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            {
                unknown_mode_count += usize::from(mode.is_none());
                unowned_private_count +=
                    usize::from(mode == Some(arkret_sdk::AgentInteractionMode::Private) && !owned);
                missing_participant_count += usize::from(target.is_none());
            }
            selected.push(
                if mode == Some(arkret_sdk::AgentInteractionMode::Private) && !owned {
                    None
                } else {
                    mode
                },
            );
        } else if own.as_ref() != Some(&mention.subject_account_id) {
            outside = true;
        }
    }
    let route = arkret_sdk::agent_mention_route_with_modes(
        scope,
        &selected,
        outside,
        mentions.iter().any(|m| m.as_audience_mention().is_some()),
    );
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    if route == arkret_sdk::AgentMentionRoute::BlockedMixedPrivateTargets {
        tracing::warn!(
            ?scope,
            selected_agent_count = selected.len(),
            unknown_mode_count,
            unowned_private_count,
            missing_participant_count,
            outside,
            audience = mentions.iter().any(|m| m.as_audience_mention().is_some()),
            "joint private mention route blocked"
        );
    }
    route
}

#[derive(Clone, Debug)]
struct OwnedAgentSidecarEnsureResult {
    sidecar_id: arkret_sdk::SidecarId,
    view: arkret_sdk::AgentSidecarView,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PendingNativeSidecarCommit {
    operation_id: arkret_sdk::ProtocolOperationId,
    sidecar_id: arkret_sdk::SidecarId,
    source_context_ref: arkret_sdk::SidecarContextRef,
    expected_phase: arkret_sdk::SidecarEnsureAcceptedPhase,
    expires_at: chrono::DateTime<chrono::Utc>,
    request: arkret_sdk::SidecarEnsureRequestBody,
}

async fn submit_frozen_sidecar_ensure<'a, F, Fut>(
    request: &'a arkret_sdk::SidecarEnsureRequestBody,
    expires_at: chrono::DateTime<chrono::Utc>,
    check_session: impl Fn() -> anyhow::Result<()>,
    mut submit: F,
) -> anyhow::Result<arkret_sdk::SidecarEnsureOutcome>
where
    F: FnMut(&'a arkret_sdk::SidecarEnsureRequestBody) -> Fut,
    Fut: std::future::Future<
            Output = arkret_sdk::http_client::Result<arkret_sdk::SidecarEnsureOutcome>,
        >,
{
    anyhow::ensure!(
        matches!(
            request,
            arkret_sdk::SidecarEnsureRequestBody::Commit(_)
                | arkret_sdk::SidecarEnsureRequestBody::Attach(_)
        ),
        "only an already frozen Sidecar commit or attach may be replayed"
    );
    for attempt in 0..3 {
        check_session()?;
        anyhow::ensure!(
            expires_at > crate::clock::now_utc(),
            "frozen Sidecar reservation expired"
        );
        let result = submit(request).await;
        check_session()?;
        match result {
            Ok(outcome) => return Ok(outcome),
            Err(error) => {
                let unconfirmed = matches!(error, arkret_sdk::http_client::Error::Http(_))
                    || matches!(error, arkret_sdk::http_client::Error::Api { status: 503, .. }
                        if error.error_code() == Some(arkret_sdk::ErrorCode::TemporarilyUnavailable));
                if !unconfirmed || attempt == 2 {
                    return Err(error.into());
                }
            }
        }
    }
    unreachable!("bounded Sidecar commit replay always returns its last result")
}

fn pending_native_sidecar_commit_key(
    controller_principal_id: &str,
    realm_id: &str,
    strand_id: &str,
) -> String {
    format!("ak.local.native_sidecar_commit.v1:{controller_principal_id}:{realm_id}:{strand_id}")
}

fn validate_native_prepared_sidecar_binding(
    create_event: Option<&arkret_sdk::Event>,
    context_attach_event: &arkret_sdk::Event,
    sidecar_id: &arkret_sdk::SidecarId,
    source_strand_id: &arkret_sdk::StrandId,
    controller_did: &arkret_sdk::Did,
    source_realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<()> {
    let controller_actor = arkret_sdk::project_did_to_core_id(controller_did)?;
    if let Some(create) = create_event
        && (create.kind != arkret_sdk::EventKind::SidecarCreate
            || create.actor_id.signing_principal_id() != &controller_actor
            || create.realm_id != *source_realm_id
            || create.scope_ref
                != (arkret_sdk::ScopeRef::Realm {
                    realm_id: source_realm_id.clone(),
                })
            || !create.payload.is_empty()
            || arkret_sdk::SidecarId::from_event_id(&create.event_id) != *sidecar_id)
    {
        anyhow::bail!("native Sidecar create draft differs from its reservation");
    }
    if context_attach_event.kind != arkret_sdk::EventKind::SidecarContextAttach
        || context_attach_event.actor_id.signing_principal_id() != &controller_actor
        || context_attach_event.realm_id != *source_realm_id
        || context_attach_event.scope_ref
            != (arkret_sdk::ScopeRef::Sidecar {
                realm_id: source_realm_id.clone(),
                sidecar_id: sidecar_id.clone(),
            })
    {
        anyhow::bail!("native Sidecar context attach draft has the wrong signed scope");
    }
    let attach: arkret_sdk::SidecarContextAttachPayload = serde_json::from_value(
        serde_json::Value::Object(context_attach_event.payload.clone().into_iter().collect()),
    )?;
    attach.validate()?;
    if attach.sidecar_id != *sidecar_id
        || attach.source_context_ref
            != (arkret_sdk::SidecarContextRef::Strand {
                strand_id: source_strand_id.clone(),
            })
    {
        anyhow::bail!("native Sidecar context attach changed its reserved source context");
    }
    if let Some(create) = create_event
        && (attach.version != 1
            || attach.predecessor_event_ref.is_some()
            || context_attach_event.semantic_refs.len() != 1
            || context_attach_event.semantic_refs[0].id != create.event_id.as_str()
            || context_attach_event.semantic_refs[0].role != "after"
            || !context_attach_event.semantic_refs[0].critical)
    {
        anyhow::bail!("new native Sidecar attach does not exactly follow its create Event");
    }
    Ok(())
}

fn accepted_native_sidecar_id(
    outcome: &arkret_sdk::SidecarEnsureOutcome,
    expected_operation_id: &arkret_sdk::ProtocolOperationId,
    expected_phase: arkret_sdk::SidecarEnsureAcceptedPhase,
    expected_sidecar_id: &arkret_sdk::SidecarId,
    expected_source_context: &arkret_sdk::SidecarContextRef,
) -> anyhow::Result<arkret_sdk::SidecarId> {
    match outcome {
        arkret_sdk::SidecarEnsureOutcome::Accepted(accepted)
            if accepted.operation_id == *expected_operation_id
                && accepted.accepted_phase == expected_phase
                && accepted.sidecar_id == *expected_sidecar_id
                && accepted.source_context_ref == *expected_source_context =>
        {
            if accepted.access_readiness == arkret_sdk::AgentSidecarAccessReadiness::Failed {
                anyhow::bail!("native Sidecar ensure completed with failed access readiness");
            }
            Ok(accepted.sidecar_id.clone())
        }
        arkret_sdk::SidecarEnsureOutcome::Accepted(_) => {
            anyhow::bail!("native Sidecar accepted outcome changed its reserved binding")
        }
        arkret_sdk::SidecarEnsureOutcome::PreparedNew(_)
        | arkret_sdk::SidecarEnsureOutcome::PreparedExisting(_) => {
            anyhow::bail!("native Sidecar commit returned another prepared outcome")
        }
    }
}

fn sign_prepared_sidecar_event(
    draft: &arkret_sdk::PreparedEventDraft,
    proof_context: crate::event_signer::ProducerProofContext,
    expected_kind: &str,
    controller_did: &arkret_sdk::Did,
    device_id: &str,
    source_realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<arkret_sdk::AuthoredEvent> {
    let digest_suite = proof_context.digest_suite;
    let controller_actor = arkret_sdk::project_did_to_core_id(controller_did)?;
    let mut event = draft.unsigned_event()?;
    let digest = arkret_sdk::Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
    if event.digest_suite() != digest_suite
        || event.kind.as_str() != expected_kind
        || event.realm_id != *source_realm_id
        || event.actor_id.signing_principal_id() != &controller_actor
        || digest != draft.event_digest
        || event.producer_proof.is_some()
    {
        anyhow::bail!("prepared Sidecar Event metadata does not match its canonical bytes");
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device signer is required for Sidecar commit"))?;
    let expected_verification_method =
        arkret_sdk::DidUrl::new(format!("{controller_did}#{device_id}"))
            .map_err(anyhow::Error::msg)?;
    if signer.device_id() != Some(device_id)
        || signer.verification_method_for_principal(controller_did)? != expected_verification_method
    {
        anyhow::bail!("active Sidecar signer is not bound to the authenticated controller device");
    }
    signer.sign_sdk_event_with_context(&mut event, proof_context)?;
    let signed_digest = arkret_sdk::Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
    if signed_digest != draft.event_digest
        || event.producer_proof.is_none()
        || event.producer_proof.as_ref().is_some_and(|proof| {
            proof.event_digest != draft.event_digest
                || proof.verification_method != expected_verification_method
        })
    {
        anyhow::bail!("signed Sidecar Event no longer matches its reservation draft");
    }
    Ok(event)
}

async fn ensure_owned_agent_sidecar(
    base_url: &str,
    api_token: String,
    trace_id: &str,
    authority: &arkret_sdk::AccountId,
    controller_did: &arkret_sdk::Did,
    device_id: &arkret_sdk::DeviceId,
    realm_id: &str,
    strand_id: &str,
    addressed_agent_ids: &[String],
    mut state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<Option<OwnedAgentSidecarEnsureResult>> {
    if addressed_agent_ids.is_empty() {
        return Ok(None);
    }
    let controller = authority.principal_id.clone();
    let source_realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let source_digest_suite = state_store
        .read()
        .station_realm_digest_suite(source_realm.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("native Sidecar source Realm is waiting for its Station frontier")
        })?;
    let source_strand = arkret_sdk::StrandId::new(strand_id.to_owned())?;
    let mut addressed = addressed_agent_ids
        .iter()
        .map(|agent_id| crate::mls_api_helpers::principal_core_id(agent_id))
        .collect::<Result<Vec<_>, _>>()?;
    addressed.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    addressed.dedup();
    if addressed.iter().any(|agent_id| agent_id == &controller) {
        anyhow::bail!("native Sidecar addressed Agents must exclude the controller");
    }

    let nonce = uuid_v7();
    let context_ref = arkret_sdk::SidecarContextRef::Strand {
        strand_id: source_strand.clone(),
    };
    let pending_key = pending_native_sidecar_commit_key(controller.as_str(), realm_id, strand_id);
    let pending = state_store
        .read()
        .load_plain_local_data(&pending_key)
        .and_then(|raw| serde_json::from_str::<PendingNativeSidecarCommit>(&raw).ok())
        .filter(|pending| {
            pending.expires_at > crate::clock::now_utc()
                && pending.source_context_ref == context_ref
        });
    if pending.is_none()
        && state_store
            .read()
            .load_plain_local_data(&pending_key)
            .is_some()
    {
        state_store.write().remove_plain_local_data(&pending_key);
    }
    let operation_id = match pending.as_ref() {
        Some(pending) => pending.operation_id.clone(),
        None => {
            arkret_sdk::ProtocolOperationId::new(format!("ak:operation:sidecar.ensure.{nonce}"))
                .map_err(anyhow::Error::msg)?
        }
    };
    let prepare = arkret_sdk::SidecarEnsureRequestBody::Prepare(
        arkret_sdk::SidecarEnsurePrepareRequestBody {
            phase: arkret_sdk::SidecarEnsurePreparePhase::Prepare,
            operation_id: operation_id.clone(),
            idempotency_key: arkret_sdk::IdempotencyKey::new(nonce).map_err(anyhow::Error::msg)?,
            source_realm_id: source_realm.clone(),
            controller_account_id: authority.clone(),
            context_ref: context_ref.clone(),
        },
    );
    tracing::info!(
        target: "sidecar",
        event = "sidecar.ensure.started",
        trace_id,
        operation_id = %operation_id,
        addressed_agent_count = addressed.len(),
    );
    let ceremony_operation_id = operation_id.clone();
    let ceremony_controller_account_id = authority.clone();
    let ceremony_controller_did = controller_did.clone();
    let ceremony_realm = source_realm.clone();
    let ceremony_strand = source_strand.clone();
    let ceremony_context = context_ref.clone();
    let ceremony_device = device_id.to_string();
    let ceremony_pending_key = pending_key.clone();
    let ceremony_fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let completion_fence = ceremony_fence.clone();
    let mut ceremony_state_store = state_store;
    let (sidecar_id, view) = crate::transport::auth::with_authed_sdk_client(
        base_url,
        api_token,
        move |http| async move {
            ceremony_fence.check()?;
            let (expected_phase, expected_sidecar_id, request, expires_at) = if let Some(pending) = pending {
                if pending.operation_id != ceremony_operation_id {
                    anyhow::bail!("durable native Sidecar commit changed its operation binding");
                }
                (pending.expected_phase, pending.sidecar_id, pending.request, pending.expires_at)
            } else {
                let prepared = http
                    .agent_sidecar_ensure(&prepare)
                    .await
                    .map_err(anyhow::Error::from)?;
                ceremony_fence.check()?;
                // Device-list refresh may fence the retained key while prepare
                // is in flight. Resolve the exact active author through the
                // ordinary Event authoring path before signing either draft.
                let proof_context = crate::event_submit::EventSubmitter::new(http.clone())
                    .with_authority(ceremony_controller_account_id.clone())
                    .with_state_store(crate::app::runtime_adapter::state_store_handle(
                        ceremony_state_store,
                    ))
                    .event_proof_context(source_digest_suite)
                    .await?;
                ceremony_fence.check()?;
                let idempotency_key =
                    arkret_sdk::IdempotencyKey::new(uuid_v7()).map_err(anyhow::Error::msg)?;
                match prepared {
                arkret_sdk::SidecarEnsureOutcome::Accepted(_) => {
                    anyhow::bail!("native Sidecar prepare skipped its signed reservation ceremony")
                }
                        arkret_sdk::SidecarEnsureOutcome::PreparedNew(
                            arkret_sdk::SidecarEnsurePreparedNewOutcome {
                            operation_id,
                            reservation_handle,
                            expires_at,
                            create_event_draft,
                            context_attach_event_draft,
                            ..
                        }) => {
                            if operation_id != ceremony_operation_id
                                || expires_at <= crate::clock::now_utc()
                            {
                                anyhow::bail!("new native Sidecar prepare returned inconsistent reservation bindings");
                            }
                            let create_event = sign_prepared_sidecar_event(
                                &create_event_draft,
                                proof_context.clone(),
                                arkret_sdk::EventKind::SidecarCreate.as_str(),
                                &ceremony_controller_did,
                                &ceremony_device,
                                &ceremony_realm,
                            )?;
                            let sidecar_id = arkret_sdk::SidecarId::from_event_id(
                                create_event.event_id(),
                            );
                            let context_attach_event = sign_prepared_sidecar_event(
                                &context_attach_event_draft,
                                proof_context,
                                arkret_sdk::EventKind::SidecarContextAttach.as_str(),
                                &ceremony_controller_did,
                                &ceremony_device,
                                &ceremony_realm,
                            )?;
                            validate_native_prepared_sidecar_binding(
                                Some(&create_event),
                                &context_attach_event,
                                &sidecar_id,
                                &ceremony_strand,
                                &ceremony_controller_did,
                                &ceremony_realm,
                            )?;
                            let request = arkret_sdk::SidecarEnsureRequestBody::Commit(
                                arkret_sdk::SidecarEnsureCommitRequestBody {
                                    phase: arkret_sdk::SidecarEnsureCommitPhase::Commit,
                                    operation_id: ceremony_operation_id.clone(),
                                    idempotency_key,
                                    reservation_handle,
                                    create_event: create_event.into_event(),
                                    context_attach_event: context_attach_event.into_event(),
                                },
                            );
                            let pending = PendingNativeSidecarCommit {
                                operation_id: ceremony_operation_id.clone(),
                                sidecar_id: sidecar_id.clone(),
                                source_context_ref: ceremony_context.clone(),
                                expected_phase: arkret_sdk::SidecarEnsureAcceptedPhase::Commit,
                                expires_at,
                                request: request.clone(),
                            };
                            {
                                ceremony_fence.check()?;
                                let barrier = {
                                    let mut store = ceremony_state_store.write();
                                    store.save_plain_local_data(ceremony_pending_key.clone(),
                                        serde_json::to_string(&pending)?,
                                    );
                                    store.begin_durable_flush()?
                                };
                                barrier.wait().await?;
                            }
                            (
                                arkret_sdk::SidecarEnsureAcceptedPhase::Commit,
                                sidecar_id,
                                request,
                                expires_at,
                            )
                        }
                        arkret_sdk::SidecarEnsureOutcome::PreparedExisting(
                            arkret_sdk::SidecarEnsurePreparedExistingOutcome {
                            operation_id,
                            reservation_handle,
                            expires_at,
                            sidecar_id,
                            context_attach_event_draft,
                            ..
                        }) => {
                            if operation_id != ceremony_operation_id
                                || expires_at <= crate::clock::now_utc()
                            {
                                anyhow::bail!("existing native Sidecar prepare returned inconsistent reservation bindings");
                            }
                            let context_attach_event = sign_prepared_sidecar_event(
                                &context_attach_event_draft,
                                proof_context,
                                arkret_sdk::EventKind::SidecarContextAttach.as_str(),
                                &ceremony_controller_did,
                                &ceremony_device,
                                &ceremony_realm,
                            )?;
                            validate_native_prepared_sidecar_binding(
                                None,
                                &context_attach_event,
                                &sidecar_id,
                                &ceremony_strand,
                                &ceremony_controller_did,
                                &ceremony_realm,
                            )?;
                            let request = arkret_sdk::SidecarEnsureRequestBody::Attach(
                                arkret_sdk::SidecarEnsureAttachRequestBody {
                                    phase: arkret_sdk::SidecarEnsureAttachPhase::Attach,
                                    operation_id: ceremony_operation_id.clone(),
                                    idempotency_key,
                                    reservation_handle,
                                    context_attach_event: context_attach_event.into_event(),
                                },
                            );
                            let pending = PendingNativeSidecarCommit {
                                operation_id: ceremony_operation_id.clone(),
                                sidecar_id: sidecar_id.clone(),
                                source_context_ref: ceremony_context.clone(),
                                expected_phase: arkret_sdk::SidecarEnsureAcceptedPhase::Attach,
                                expires_at,
                                request: request.clone(),
                            };
                            {
                                ceremony_fence.check()?;
                                let barrier = {
                                    let mut store = ceremony_state_store.write();
                                    store.save_plain_local_data(ceremony_pending_key.clone(),
                                        serde_json::to_string(&pending)?,
                                    );
                                    store.begin_durable_flush()?
                                };
                                barrier.wait().await?;
                            }
                            (
                                arkret_sdk::SidecarEnsureAcceptedPhase::Attach,
                                sidecar_id,
                                request,
                                expires_at,
                            )
                        }
                }
            };
            let accepted = submit_frozen_sidecar_ensure(
                &request,
                expires_at,
                || ceremony_fence.check(),
                |request| http.agent_sidecar_ensure(request),
            ).await?;
            let sidecar_id = accepted_native_sidecar_id(
                &accepted,
                &ceremony_operation_id,
                expected_phase,
                &expected_sidecar_id,
                &ceremony_context,
            )?;
            let view = http
                .agent_sidecar_get(&sidecar_id)
                .await
                .map_err(anyhow::Error::from)?;
            ceremony_fence.check()?;
            crate::sidecar::validate_agent_sidecar_view(&view)?;
            if view.sidecar.id != sidecar_id
                || view.sidecar.realm_id != ceremony_realm
                || view.sidecar.controller_account_id != ceremony_controller_account_id
            {
                anyhow::bail!("native Sidecar view differs from its accepted ceremony");
            }
            Ok::<_, anyhow::Error>((sidecar_id, view))
        },
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))?;
    completion_fence.check()?;
    {
        let barrier = {
            let mut store = state_store.write();
            store.remove_plain_local_data(&pending_key);
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }
    if addressed
        .iter()
        .any(|agent_id| !view.desired_agent_ids.contains(agent_id))
    {
        anyhow::bail!("an addressed Agent is not a desired member of this Realm Sidecar");
    }
    tracing::info!(
        target: "sidecar",
        event = "sidecar.ensure.completed",
        trace_id,
        operation_id = %operation_id,
        sidecar_id = %sidecar_id,
        access_readiness = ?view.access_readiness,
    );
    Ok(Some(OwnedAgentSidecarEnsureResult { sidecar_id, view }))
}

/// The native Sidecar scope whose accepted MLS epoch is used for encryption.
fn sidecar_mls_scope(view: &arkret_sdk::AgentSidecarView) -> arkret_sdk::SidecarId {
    view.sidecar.id.clone()
}

struct SourceRoutedSidecarMessageOutcome {
    event_id: String,
    history_pending: Option<String>,
}

impl SourceRoutedSidecarMessageOutcome {
    fn after_accept(event_id: String, history: anyhow::Result<()>) -> Self {
        Self {
            event_id,
            history_pending: history.err().map(|error| format!("{error:#}")),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "tests/sidecar_accepted_readback.rs"]
mod sidecar_accepted_readback_tests;

#[allow(clippy::too_many_arguments)]
async fn submit_source_routed_sidecar_message(
    base_url: &str,
    api_token: String,
    controller_principal_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    source_realm_id: &str,
    attached_source_strand_id: &str,
    routed_source_strand_id: &str,
    source_event_id: Option<&str>,
    body: &str,
    mentions: &[MentionNode],
    addressed_agent_ids: &[String],
    mut state_store: SyncSignal<LocalStateStore>,
    view: &arkret_sdk::AgentSidecarView,
) -> anyhow::Result<SourceRoutedSidecarMessageOutcome> {
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let request_epoch = crate::identity::device_directory::session_cache_epoch();
    let active_account = consume_context::<crate::app::SessionContext>().active_account;
    let active_store = state_store;
    let active = move || {
        fence.check_session_identity().is_ok()
            && crate::identity::device_directory::session_cache_epoch() == request_epoch
            && active_store.peek().active_authority().as_ref() == Some(authority)
            && active_account.peek().as_ref().is_some_and(|account| {
                &account.authority == authority && &account.device_id == device_id
            })
    };
    anyhow::ensure!(
        active(),
        "private send belongs to a replaced account session"
    );
    crate::sidecar::validate_agent_sidecar_view(view)?;
    crate::sidecar::cached_sidecar_exchange_projections(
        &state_store.read(),
        authority,
        source_realm_id,
    )?;
    if attached_source_strand_id != routed_source_strand_id {
        anyhow::bail!("native Sidecar send source differs from its attached context");
    }
    if view.sidecar.realm_id.as_str() != source_realm_id
        || view.access_readiness != arkret_sdk::AgentSidecarAccessReadiness::Ready
        || !view.mls_context.current_controller_device_ready
    {
        anyhow::bail!("native Sidecar MLS access is not ready for a routed write");
    }
    let group_id = view
        .mls_context
        .mls_group_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("native Sidecar has no accepted MLS group"))?;
    let effective_scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: view.sidecar.realm_id.clone(),
        sidecar_id: view.sidecar.id.clone(),
    };
    let snapshot = state_store
        .read()
        .mls_checkpoint_for_scope_and_group(&effective_scope, group_id.as_str())
        .ok_or_else(|| anyhow::anyhow!("native Sidecar MLS snapshot is unavailable"))?;
    if snapshot.group_id != group_id.as_str() {
        anyhow::bail!("native Sidecar MLS snapshot differs from its accepted group");
    }
    let mut addressed = addressed_agent_ids
        .iter()
        .map(|agent_id| crate::mls_api_helpers::principal_core_id(agent_id))
        .collect::<Result<Vec<_>, _>>()?;
    addressed.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    addressed.dedup();
    if addressed.is_empty() {
        anyhow::bail!("Select an Agent with @ before sending this private message");
    }
    if addressed
        .iter()
        .any(|agent_id| !view.effective_agent_ids.contains(agent_id))
    {
        anyhow::bail!("every addressed Agent must have effective native Sidecar MLS access");
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
    let content_value = sdk_payload_value(content.to_value(), "Sidecar routed content serialize")?;
    let content_bytes = serde_json::to_vec(&content_value)?;
    let content_for_sidecar = String::from_utf8(content_bytes.clone())?;
    let addressed_strings = addressed
        .iter()
        .map(|agent_id| agent_id.as_str().to_owned())
        .collect::<Vec<_>>();
    let intent_digest = crate::sidecar::sidecar_submission_intent_digest(
        attached_source_strand_id,
        body,
        &addressed_strings,
    );
    let Some(_submission_guard) = crate::sidecar::try_begin_sidecar_submission(
        controller_principal_id,
        attached_source_strand_id,
        &intent_digest,
    ) else {
        anyhow::bail!("this native Sidecar request is already being submitted");
    };
    let prior = crate::sidecar::load_pending_sidecar_submission(
        &state_store.read(),
        controller_principal_id,
        attached_source_strand_id,
        &intent_digest,
    );
    let request_context = prior
        .as_ref()
        .map(|pending| pending.request_context.clone())
        .unwrap_or(arkret_sdk::AgentSidecarExchangeRequestContext {
            source_track_ref: arkret_sdk::SidecarSourceTrackRef {
                realm_id: view.sidecar.realm_id.clone(),
                strand_id: arkret_sdk::StrandId::new(attached_source_strand_id.to_owned())?,
                track_name: "discussion".to_owned(),
            },
            source_hlc: crate::signing_stamp::issue_protocol_hlc(
                controller_principal_id,
                device_id.as_str(),
                source_realm_id,
            )?,
            client_order_key: uuid_v7(),
            addressed_agent_ids: addressed.clone(),
            coordinator_agent_id: (addressed.len() > 1).then(|| addressed[0].clone()),
            source_checkpoint_anchor_id: source_event_id
                .filter(|anchor| !anchor.trim().is_empty())
                .and_then(|anchor| arkret_sdk::EventId::new(anchor.to_owned()).ok()),
        });
    let exchange_id = prior
        .as_ref()
        .map(|pending| pending.exchange_id.clone())
        .unwrap_or_else(uuid_v7);
    let binding = arkret_sdk::AgentSidecarEventExchangeBinding {
        schema: arkret_sdk::SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1.to_owned(),
        exchange_id: exchange_id.clone(),
        role: arkret_sdk::AgentSidecarExchangeRole::Request,
        request_event_id: None,
        completes_exchange: None,
        coordinator_assignment_event_id: None,
        request_context: Some(request_context.clone()),
    };
    binding.validate_shape()?;
    let mut message_metadata = arkret_sdk::MessageMetadata::default();
    crate::sidecar::set_sidecar_exchange_binding(&mut message_metadata, &binding)?;
    let metadata_bytes = serde_json::to_vec(&message_metadata)?;
    let message_id = new_chat_local_id();
    let api = crate::transport::auth::authed_api_with_sync(base_url, api_token.clone(), None)?;
    let build = crate::views::secure_send::build_secure_send(
        &api,
        state_store,
        source_realm_id,
        authority,
        controller_principal_id,
        device_id,
        attached_source_strand_id,
        &message_id,
        None,
        &content_bytes,
        Some(&metadata_bytes),
        None,
        Some(sidecar_mls_scope(view)),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let local_operation_id = build.message_local_operation_id.to_string();
    let pending = crate::sidecar::PendingSidecarSubmission {
        controller_account_id: authority.clone(),
        sidecar_id: view.sidecar.id.clone(),
        source_strand_id: attached_source_strand_id.to_owned(),
        exchange_id,
        request_context,
        message_id: message_id.clone(),
        local_operation_id: local_operation_id.clone(),
    };
    {
        anyhow::ensure!(
            active(),
            "private send belongs to a replaced account session"
        );
        let barrier = {
            let mut store = state_store.write();
            crate::sidecar::save_pending_sidecar_submission(&mut store, &intent_digest, &pending)?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }
    anyhow::ensure!(
        active(),
        "private send belongs to a replaced account session"
    );
    let outcome = crate::views::secure_send::submit_secure_send(
        &api,
        state_store,
        build,
        source_realm_id,
        None,
    )
    .await;
    let (event_id, status) = match outcome {
        crate::views::secure_send::SecureSendOutcome::Sent { event_id, status } => {
            (event_id, status)
        }
        crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
            anyhow::bail!(message)
        }
        crate::views::secure_send::SecureSendOutcome::MessageAuthoringFailed { failure } => {
            anyhow::bail!(crate::i18n::tr(
                crate::views::chat::model::chat_authoring_failure_message(&failure)
            ))
        }
    };
    let history = async {
        anyhow::ensure!(
            active(),
            "accepted private write belongs to a replaced account session"
        );
        let (barrier, plaintext_write) = {
            let mut store = state_store.write();
            // The read-side projection derives the protocol message id from the
            // accepted event id (`MessageId::from_event_id`); the raw-op record
            // and the author plaintext sidecar must key on that same derived id,
            // not the pre-submit local id, or the author's own body is orphaned
            // on echo / reload.
            let protocol_message_id = arkret_sdk::EventId::new(event_id.clone())
                .ok()
                .map(|accepted_event_id| {
                    arkret_sdk::MessageId::from_event_id(&accepted_event_id)
                        .as_str()
                        .to_owned()
                })
                .unwrap_or_else(|| message_id.clone());
            store.append_raw_operation(
                local_operation_id,
                Some(source_realm_id.to_owned()),
                json!({
                    "event_id": event_id.clone(),
                    "kind": event_kind_str::MESSAGE_CREATE,
                    "actor_id": controller_principal_id,
                    "strand_id": attached_source_strand_id,
                    "message_id": protocol_message_id,
                    "encrypted_content": true,
                    "status": status,
                }),
            );
            store.save_private_plaintext(
                source_realm_id,
                attached_source_strand_id,
                &format!("message:{protocol_message_id}"),
                &content_for_sidecar,
            );
            crate::sidecar::remove_pending_sidecar_submission(
                &mut store,
                controller_principal_id,
                attached_source_strand_id,
                &intent_digest,
            );
            (
                store.begin_durable_flush()?,
                store.e2ee_plaintext_cache_secure_write()?,
            )
        };
        barrier.wait().await?;
        if let Some((key, Some(bytes))) = plaintext_write {
            crate::secure_key_store::default_secure_key_store("inkson")
                .store_secret_durable(&key, &bytes)
                .await?;
        }
        anyhow::ensure!(
            active(),
            "accepted private write belongs to a replaced account session"
        );
        anyhow::ensure!(
            status == "committed",
            "private write is queued; awaiting its committed native history"
        );
        crate::realm_events_engine::refresh_accepted_sidecar(
            api.http(),
            authority,
            request_epoch,
            &view.sidecar.realm_id,
            &view.sidecar.id,
            &arkret_sdk::EventId::new(event_id.clone())?,
            crate::app::runtime_adapter::state_store_handle(state_store),
            active,
        )
        .await?;
        Ok(())
    }
    .await;
    // The Station has already answered for the frozen identity. A recovery
    // read failure must never turn that write into a send failure or reauthor it.
    Ok(SourceRoutedSidecarMessageOutcome::after_accept(
        event_id, history,
    ))
}

fn sidecar_agent_label(agent_ids: &[String], participants: &[SpaceParticipant]) -> String {
    let labels = agent_ids
        .iter()
        .map(|agent_id| {
            participants
                .iter()
                .find(|participant| participant.principal_id.as_str() == agent_id)
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

#[derive(Clone, PartialEq)]
pub(super) struct SidecarCloseCutFence {
    authority: arkret_sdk::AccountId,
    device: arkret_sdk::DeviceId,
    realm: String,
    generation: u64,
    authoring_digest: String,
    cut_digest: String,
}

impl SidecarCloseCutFence {
    /// Capture the same complete verified cut used by the read projection.
    /// This is a disposable authoring fence, never a persisted authority.
    pub(super) fn capture(
        store: &LocalStateStore,
        authority: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        realm: &str,
    ) -> Option<Self> {
        if store.active_authority().as_ref() != Some(authority)
            || store.current_reset_required()
            || store.realm_detail_invalidated(realm)
        {
            return None;
        }
        let local = store.load().device_authoring_authority?;
        if &local.account_id != authority || &local.device_id != device {
            return None;
        }
        let (snapshot, _) = store.verified_sidecar_inputs(realm).ok()?;
        Some(Self {
            authority: authority.clone(),
            device: device.clone(),
            realm: realm.to_owned(),
            generation: store.current_generation(),
            authoring_digest: arkret_sdk::canonical::canonical_sha256(&local).ok()?,
            cut_digest: arkret_sdk::canonical::canonical_sha256(&snapshot).ok()?,
        })
    }

    fn check(
        &self,
        store: &LocalStateStore,
        authority: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        realm: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            Self::capture(store, authority, device, realm).as_ref() == Some(self),
            "Sidecar close belongs to a replaced account, device or verified current cut"
        );
        Ok(())
    }
}

fn check_sidecar_close_authoring(
    cut: &SidecarCloseCutFence,
    session: &crate::transport::auth::AuthoringSessionFence,
    store: &LocalStateStore,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    realm: &str,
) -> anyhow::Result<()> {
    session.check()?;
    anyhow::ensure!(
        crate::secure_key_store::active_device_seed_scope()
            .is_some_and(|scope| { &scope.authority == authority && &scope.device_id == device }),
        "Sidecar close signer belongs to another account or device"
    );
    cut.check(store, authority, device, realm)
}

#[cfg(test)]
#[path = "tests/sidecar_close_fence.rs"]
mod sidecar_close_fence_tests;

async fn drive_sidecar_completion_closes(
    base_url: String,
    token: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    realm: String,
    state_store: SyncSignal<LocalStateStore>,
    closes: Vec<(
        arkret_sdk::AgentSidecarExchangeProjection,
        arkret_sdk::AgentSidecarExchangeControl,
    )>,
    close_cut: Option<SidecarCloseCutFence>,
) -> anyhow::Result<()> {
    let Some(close_cut) = close_cut else {
        return Ok(());
    };
    let session = crate::transport::auth::AuthoringSessionFence::capture()?;
    if check_sidecar_close_authoring(
        &close_cut,
        &session,
        &state_store.read(),
        &authority,
        &device_id,
        &realm,
    )
    .is_err()
    {
        return Ok(());
    }
    let api = crate::transport::auth::authed_api_with_sync(&base_url, token, None)?;
    for (projection, control) in closes {
        anyhow::ensure!(
            projection.controller_account_id == authority
                && projection.source_track_ref.realm_id.as_str() == realm,
            "Sidecar close projection crosses its controller or source Realm"
        );
        let digest = arkret_sdk::canonical::canonical_sha256(&control)?;
        let Some(_guard) = crate::sidecar::try_begin_sidecar_submission(
            authority.principal_id.as_str(),
            projection.source_track_ref.strand_id.as_str(),
            &digest,
        ) else {
            continue;
        };
        let handle = crate::app::runtime_adapter::state_store_handle(state_store);
        if crate::event_submit::retained_sidecar_control_request(
            &authority,
            &projection.sidecar_id,
            &projection.private_request_event_id,
            &handle,
        )
        .await?
        {
            continue;
        }
        // The retained queue lookup can suspend while another device closes
        // this exchange or the foreground account is replaced. Never author
        // the frozen proposal after either boundary has changed.
        if check_sidecar_close_authoring(
            &close_cut,
            &session,
            &state_store.read(),
            &authority,
            &device_id,
            &realm,
        )
        .is_err()
        {
            return Ok(());
        }
        let mut build = crate::views::secure_send::build_sidecar_exchange_control_send(
            state_store,
            &realm,
            &authority,
            authority.principal_id.as_str(),
            &device_id,
            projection.source_track_ref.strand_id.as_str(),
            projection.sidecar_id,
            &control,
        )
        .await
        .map_err(anyhow::Error::msg)?;
        check_sidecar_close_authoring(
            &close_cut,
            &session,
            &state_store.read(),
            &authority,
            &device_id,
            &realm,
        )?;
        let crate::views::secure_send::SecureWritePlan::Control(plan) = build.message_plan else {
            anyhow::bail!("Sidecar close must remain a controller control Event");
        };
        let plan_cut = close_cut.clone();
        let plan_session = session.clone();
        let plan_authority = authority.clone();
        let plan_device = device_id.clone();
        let plan_realm = realm.clone();
        // submit_secure_send awaits the sender-ratchet durability barrier
        // before invoking this plan. Recheck at that actual authoring point.
        build.message_plan =
            crate::views::secure_send::SecureWritePlan::Control(Box::new(move |accepted| {
                check_sidecar_close_authoring(
                    &plan_cut,
                    &plan_session,
                    &state_store.read(),
                    &plan_authority,
                    &plan_device,
                    &plan_realm,
                )
                .map_err(|error| error.to_string())?;
                plan(accepted)
            }));
        match crate::views::secure_send::submit_secure_send(&api, state_store, build, &realm, None)
            .await
        {
            crate::views::secure_send::SecureSendOutcome::Sent { .. } => {}
            crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
                anyhow::bail!(message)
            }
            crate::views::secure_send::SecureSendOutcome::MessageAuthoringFailed { .. } => {
                anyhow::bail!("Sidecar close was refused by the authoring gate")
            }
        }
    }
    Ok(())
}

fn composer_mention_nodes(
    mentions_enabled: bool,
    body: &str,
    picker: &[crate::messaging::mentions::MentionCandidate],
    principal_id: &str,
) -> Vec<MentionNode> {
    if !mentions_enabled {
        return Vec::new();
    }
    let mut mentions = parse_mention_nodes(body);
    for chip in picker {
        if mentions.iter().any(|node| {
            node.as_mention()
                .is_some_and(|mention| mention.subject_account_id == chip.subject_account_id)
        }) {
            continue;
        }
        let insert_label = chip.insert_label().to_owned();
        // 0364 D2: an Agent mention needs an explicitly selected chip carrying
        // a complete AccountId and its visible inserted text. A stale chip or
        // raw controller/slug token must not become a target.
        if chip.is_agent
            && (!chip.agent_slug_at_time.is_empty()
                || !chip.controller_handle_at_time.is_empty()
                || chip.controller_subject_account_id.is_some()
                || !body.contains(&format!("@{insert_label}")))
        {
            continue;
        }
        let parsed_handle = (!chip.is_agent)
            .then(|| crate::identity::handle::parse_user_handle(&insert_label))
            .flatten();
        let mut mention = arkret_sdk::Mention::new(chip.subject_account_id.clone())
            .with_mention_text_original(format!("@{insert_label}"));
        if !chip.display_name.trim().is_empty() {
            mention = mention.with_display_name_at_time(chip.display_name.clone());
        }
        if let Some(handle) =
            parsed_handle.and_then(|parsed| arkret_sdk::Handle::parse(&parsed.handle).ok())
        {
            mention = mention.with_handle_at_time(handle);
        }
        mentions.push(MentionNode::mention(mention));
    }
    // `@me` addresses this client's own account, which it knows in full. If
    // the local account cannot be assembled there is no subject to address and
    // no mention node is written.
    if crate::messaging::mentions::contains_self_mention_token(body)
        && let Ok(self_actor) = crate::mls_api_helpers::local_account_actor_id(principal_id)
        && let Some(self_account) = self_actor.as_account_id()
        && !mentions.iter().any(|node| {
            node.as_mention()
                .is_some_and(|mention| &mention.subject_account_id == self_account)
        })
    {
        mentions.push(MentionNode::mention(
            arkret_sdk::Mention::new(self_account.clone())
                .with_mention_text_original("@me".to_owned()),
        ));
    }
    mentions
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
    principal_id: arkret_sdk::DidCoreId,
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
    /// Keep the target-owned state alive while its source current is unavailable,
    /// without mounting any timeline or authoring controls.
    #[props(default)]
    source_suspended: bool,
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
    #[cfg(feature = "wasm-localstorage-secrets-test")]
    {
        use_hook(move || {
            trace_private_send_stage(if embedded {
                "embedded_chat_mounted"
            } else {
                "chat_mounted"
            });
        });
        use_drop(move || {
            trace_private_send_stage(if embedded {
                "embedded_chat_unmounted"
            } else {
                "chat_unmounted"
            });
        });
    }
    // A4 — base_url / state_store from session context instead of props.
    let session_context = crate::app::SessionContext::get();
    let base_url = session_context.base_url.read().clone();
    let state_store = session_context.state_store;
    let Some(active_account) = session_context.active_account.read().clone() else {
        return rsx! {};
    };
    let authority = active_account.authority.clone();
    let did = active_account.did().clone();
    let account_device_id = active_account.device_id.clone();
    let principal_core_id = principal_id.clone();
    let principal_id = principal_id.as_str().to_owned();
    let sidecar_session_state = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    // Embedded Strand shells do not receive a route-owned Sidecar prop. Read
    // the same hosted session that renders the context bar so message
    // projection, privacy gates, and the composer cannot diverge after an
    // in-place activation.
    let hosted_sidecar_session = sidecar_session_state();
    let initial_sidecar_session = sidecar_session
        .or_else(|| {
            hosted_sidecar_session
                .filter(|session| session.matches_route(&selected_realm_id, &initial_strand_id))
        })
        .filter(|session| session.controller_account_id == authority);
    let controller = use_chat_controller(
        &selected_realm_id,
        &initial_strand_id,
        &authority,
        &account_device_id,
    );
    let sidecar_route_pending = use_signal(|| false);
    let selected_source_strand = (controller.selected_channel)();
    let sidecar_session = initial_sidecar_session
        .filter(|session| session.matches_route(&selected_realm_id, &selected_source_strand));
    let navigator = use_navigator();
    let ChatController {
        channels,
        selected_channel,
        messages,
        draft: _,
        typing_throttle: _,
        compose_dragover: _,
        compose_upload_status: _,
        shared_pins,
        private_saved_targets: _,
        private_saved_account_data: _,
        message_context_menu: _,
        moderation_report_draft: _,
        moderation_report_pending: _,
        mut new_channel_name,
        mut new_channel_topic,
        mut new_channel_create_card,
        mut create_dialog_open,
        strand_watch_level: _,
        strand_watch_current: _,
        strand_watch_pending: _,
        strand_watch_request: _,
        strand_watch_refresh: _,
        watch_level_menu_open: _,
        mut status_msg,
        queued_outbound_local_operation_ids,
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
        agent_participation_visibility: _,
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
        promoted_targets: _,
        latest_read_cursor: _,
        blocked_show_anyway: _,
        account_display_name,
        mut track_filter,
        mut left_panel_open,
        eligible_circle_scopes,
        eligible_circle_scope_request_key_seen: _,
        eligible_circle_scope_request_in_flight: _,
        mut new_channel_scope,
        sidecar_send_pending: _,
        member_handle_fetching: _,
    } = controller;
    let blocked_actor_id_set =
        crate::account_data::blocked_message_actor_ids(&state_store.read().client_blocklist());
    let sidecar_mode = sidecar_session.is_some();
    let mut right_panel = use_signal(move || {
        if sidecar_mode {
            None
        } else {
            Option::<DiscussionSidePanel>::Some(DiscussionSidePanel::Users)
        }
    });
    let selected_channel_value = selected_channel();
    use_effect({
        let authority = authority.clone();
        let realm = selected_realm_id.clone();
        move || {
            let strands = arkret_sdk::StrandId::new(selected_channel())
                .ok()
                .into_iter()
                .collect();
            state_store.read().set_product_current_demand(
                &authority,
                &realm,
                Some(strands),
                Vec::new(),
            );
        }
    });
    use_drop({
        let authority = authority.clone();
        let realm = selected_realm_id.clone();
        move || {
            state_store
                .read()
                .set_product_current_demand(&authority, &realm, None, Vec::new())
        }
    });
    let all_channels = channels();
    let timeline_basis =
        timeline_projection::use_timeline_projection_basis(state_store, realm_live_epoch);
    let sidecar_timeline = sidecar_projection::use_sidecar_timeline_projection(
        state_store,
        timeline_basis,
        authority.clone(),
        account_device_id.clone(),
        selected_realm_id.clone(),
        crate::identity::device_directory::session_cache_epoch(),
    );
    let private_timeline = sidecar_timeline.read();
    let sidecar_exchange_current = private_timeline.current.clone();
    let private_sidecar_event_ids = private_timeline.private_event_ids.clone();
    let sidecar_privacy_gate = private_timeline.privacy_gate.clone();
    drop(private_timeline);
    use_effect({
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let authority = authority.clone();
        let device = account_device_id.clone();
        move || {
            let projection = sidecar_timeline.read();
            let closes = projection.closes.clone();
            let close_cut = projection.close_cut.clone();
            drop(projection);
            if closes.is_empty() {
                return;
            }
            let base = base.clone();
            let realm = realm.clone();
            let authority = authority.clone();
            let device = device.clone();
            let credential = token();
            spawn(async move {
                if drive_sidecar_completion_closes(
                    base,
                    credential,
                    authority,
                    device,
                    realm,
                    state_store,
                    closes,
                    close_cut,
                )
                .await
                .is_err()
                {
                    tracing::warn!(
                        "Sidecar completion close is awaiting verified recovery or durable submission"
                    );
                }
            });
        }
    });
    let filter_value = track_filter();
    let (visible_channels, selected_channel_info) =
        discussion_channels_for_surface(&all_channels, &selected_channel_value, &filter_value);
    let visible_channels_empty = visible_channels.is_empty();
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
    // Unknown scope current keeps the secure path blocked until verification.
    let selected_scope_circle = selected_channel_info.as_ref().and_then(|channel| {
        channel
            .scope_circle
            .as_ref()
            .map(|circle| circle.circle_id.clone())
    });
    let send_scope = selected_channel_info
        .as_ref()
        .and_then(|channel| channel.effective_scope(&selected_realm_id));
    let scope_send_probe = crate::views::secure_send::use_scope_send_probe(
        state_store,
        send_scope.clone(),
        account_device_id.clone(),
    );
    let scope_readiness_checking = scope_send_probe.checking;
    let scope_send_gate = scope_send_probe.gate;
    // This probe belongs to the selected original Strand. A private Agent
    // draft has its own native Sidecar probe in ChatComposer; merely showing
    // private history must not change ordinary message encryption or readiness.
    let selected_channel_security_encrypted = if direct_mode {
        true
    } else {
        !matches!(
            scope_send_gate.as_ref(),
            Some(crate::mls::send_gate::MlsSendGate::Plaintext)
        )
    };
    let direct_message_authority =
        crate::app::SessionContext::get()
            .active_account()
            .and_then(|account| {
                crate::mls::direct_binding::message_authority(
                    &state_store.read(),
                    &selected_realm_id,
                    &arkret_sdk::ActorId::account(account.authority),
                )
            });
    let mut selected_realm_pending_mls_binding_reason = if selected_scope_circle.is_none() {
        state_store
            .read()
            .realm_pending_mls_binding_reason(&selected_realm_id)
    } else {
        None
    };
    if (selected_channel_security_encrypted || direct_mode)
        && selected_realm_pending_mls_binding_reason.is_none()
    {
        let installed = match scope_send_gate.as_ref() {
            Some(crate::mls::send_gate::MlsSendGate::Encrypted(current)) => {
                crate::current_projection::ScopeMlsCurrent::Activated(current.clone())
            }
            Some(crate::mls::send_gate::MlsSendGate::Plaintext) => {
                crate::current_projection::ScopeMlsCurrent::NotActivated
            }
            None if scope_readiness_checking => send_scope
                .as_ref()
                .map(|scope| {
                    // Presentation only: authoring still requires the independent
                    // durable send probe to finish restoring private state.
                    state_store.read().installed_scope_mls_current(scope)
                })
                .unwrap_or(crate::current_projection::ScopeMlsCurrent::Unknown),
            None => crate::current_projection::ScopeMlsCurrent::Unknown,
        };
        let local_epoch = send_scope.as_ref().and_then(|scope| {
            state_store
                .read()
                .mls_checkpoint_for_scope(scope)
                .map(|checkpoint| checkpoint.epoch)
        });
        if let Some(reason) = match installed {
            crate::current_projection::ScopeMlsCurrent::Activated(current) => match local_epoch {
                Some(epoch) if epoch != current.epoch => Some(format!(
                    "encryption_transition_pending: waiting for the accepted MLS epoch {}",
                    current.epoch
                )),
                _ => None,
            },
            crate::current_projection::ScopeMlsCurrent::NotActivated => Some(
                "encryption_policy_pending: this scope has no accepted MLS Genesis yet".to_owned(),
            ),
            crate::current_projection::ScopeMlsCurrent::Unknown => Some(
                "encryption_policy_pending: waiting for the scope's verified current state"
                    .to_owned(),
            ),
        } {
            selected_realm_pending_mls_binding_reason = Some(reason);
        } else {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let roster_matches = if selected_scope_circle.is_none() {
                crate::mls::runtime::realm_mls_roster_matches_complete_membership_hint(
                    &state_store.read(),
                    secure_store.as_ref(),
                    &selected_realm_id,
                    &authority,
                    &account_device_id,
                )
            } else {
                None
            };
            let local_group_available =
                crate::mls::runtime::mls_group_member_actor_ids_for_effective_scope(
                    &state_store.read(),
                    secure_store.as_ref(),
                    &selected_realm_id,
                    selected_scope_circle.as_deref(),
                    &authority,
                    &account_device_id,
                )
                .is_some();
            if !local_group_available {
                selected_realm_pending_mls_binding_reason = Some(
                    "Waiting for this device's encryption keys. Keep this conversation open to receive the MLS Welcome."
                        .to_owned(),
                );
            } else if roster_matches == Some(false) {
                selected_realm_pending_mls_binding_reason = Some(
                    "encryption_transition_pending: synced roster differs from the verified MLS group"
                        .to_owned(),
                );
            }
        }
    }
    if selected_realm_pending_mls_binding_reason.is_none()
        && (direct_mode
            || state_store
                .read()
                .realm_collaboration_role(&selected_realm_id)
                == Some(arkret_sdk::CollaborationRealmRole::DirectConversation))
        && direct_message_authority.is_none()
    {
        selected_realm_pending_mls_binding_reason =
            Some("Waiting for verified conversation authority and encryption keys.".to_owned());
    }
    let scope_send_ready = scope_send_gate.is_some();
    let send_readiness_checking =
        scope_readiness_checking && selected_realm_pending_mls_binding_reason.is_none();
    if !scope_send_ready && selected_realm_pending_mls_binding_reason.is_none() {
        selected_realm_pending_mls_binding_reason = Some(
            "Waiting for this scope's verified send state and this device's local encryption keys."
                .to_owned(),
        );
    }
    let selected_realm_pending_mls_binding = selected_realm_pending_mls_binding_reason.is_some();
    let sidecar_security_label = sidecar_session.as_ref().map(|session| {
        if !session.membership_ready() {
            "Reconciling access"
        } else {
            "E2EE"
        }
    });
    let sidecar_send_block_reason = sidecar_session.as_ref().and_then(|session| {
        if let Err(error) = &sidecar_exchange_current {
            Some(format!("Sidecar exchange is unavailable: {error}"))
        } else if !session.membership_ready() {
            Some(format!(
                "Private access is still reconciling for {} principal(s). Sending is disabled until the native Sidecar MLS snapshot is available on this device.",
                session.pending_reconciliation_count()
            ))
        } else {
            None
        }
    });
    // Fold the durable lifecycle log from verified Events. Bare controller
    // rows have no signed scope provenance and cannot seed the shared view.
    // Folding the complete durable operation log is intentionally memoized.
    // Presence heartbeats, panel toggles, typing timers, and composer changes
    // all re-render ChatPanel; repeating the full lifecycle fold on each of
    // those unrelated edges can monopolize the WASM main thread once an
    // account has a substantial history, making the entire browser appear
    // hung even though network traffic stays quiet.
    let ordinary_timeline = timeline_projection::use_ordinary_timeline_projection(
        state_store,
        timeline_basis,
        messages,
        principal_id.clone(),
        authority.clone(),
        account_device_id.clone(),
        crate::identity::device_directory::session_cache_epoch(),
    );
    let merged_timeline = use_memo(move || {
        let mut rows = ordinary_timeline.read().clone();
        merge_chat_messages(&mut rows, sidecar_timeline.read().messages.clone());
        rows
    });
    let sidecar_projection = sidecar_session
        .as_ref()
        .map(|session| session.source_strand_id.clone());
    let visible_timeline = use_memo(use_reactive(
        (
            &selected_channel_value,
            &selected_realm_id,
            &sidecar_projection,
        ),
        move |(strand, realm, source)| {
            let private = sidecar_timeline.read();
            let projections = private.current.as_ref().cloned().unwrap_or_default();
            project_visible_messages(
                &merged_timeline.read(),
                &strand,
                &realm,
                source.as_deref(),
                &projections,
                private.current.is_ok(),
            )
        },
    ));
    let all_messages_snapshot = merged_timeline.read();
    let visible_messages = visible_timeline.read();
    // Context props carry row changes. Retain the mounted feed across sync and
    // lifecycle updates so its scroll position and focused controls survive.
    let timeline_scope_key = format!("{selected_realm_id}\u{1f}{selected_channel_value}");
    // P3B.2.4 — per-strand Circle-scope lookup used by the
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
    let participant_projection = state_store.read().realm_tree_projection(&selected_realm_id);
    let account_display_label = account_display_name();
    let mut participants = space_participants(
        participant_projection.as_ref(),
        &state_store.read(),
        &selected_realm_id,
        &principal_id,
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
    let projected_member_ids = participants
        .iter()
        .filter_map(|participant| participant.actor_id.as_ref().map(ToString::to_string))
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
            &principal_id,
            own_controller_handle.as_deref(),
        );
        enrich_authoritative_agent_metadata(
            &mut agent_metadata,
            agent_metadata_from_mentions(&all_messages_snapshot),
        );
        let joined_members = state_store
            .read()
            .complete_joined_member_hint_for_realm(&selected_realm_id)
            .ok()
            .flatten();
        upsert_joined_owned_agent_participants(
            &mut participants,
            joined_members.as_ref(),
            &agent_metadata,
            &principal_id,
        );
        upsert_agent_participants(&mut participants, &agent_metadata, &principal_id);
        annotate_agent_participants_with_metadata(&mut participants, &agent_metadata);
    }
    let participants_for_messages = participants.clone();

    let mut known_agent_ids = participants_for_messages
        .iter()
        .filter(|participant| participant.is_agent)
        .map(|participant| participant.principal_id.to_string())
        .collect::<Vec<_>>();
    known_agent_ids.sort();
    known_agent_ids.dedup();
    // The participation resource is controller-self-only. Remote agents are
    // never probed here; they become roster-visible only through already
    // visible reply history, which avoids both forbidden requests and agent
    // policy enumeration.
    let readable_participation_agent_ids =
        readable_participation_agent_ids(&participants_for_messages, &principal_id);
    // A readable history baseline does not require this endpoint's private
    // sending state. Keep the restorable-key probe on the composer above.
    let shared_sync_finished = initial_sync_finished()
        && if sidecar_mode {
            sidecar_session
                .as_ref()
                .is_some_and(|session| session.membership_ready())
        } else {
            let store = state_store.read();
            !store.current_reset_required()
                && !store.realm_detail_invalidated(&selected_realm_id)
                && send_scope.as_ref().is_some_and(|scope| {
                    !matches!(
                        store.installed_scope_mls_current(scope),
                        crate::current_projection::ScopeMlsCurrent::Unknown
                    )
                })
        };
    // Participation is a durable Realm projection. The account cursor is an
    // opaque resume checkpoint and can be re-minted for typing/receipts/calls;
    // reduce it to the one useful transition (bootstrap is ready) and use the
    // Realm epoch for subsequent durable invalidation.
    let account_sync_ready = crate::app::account_sync_ready(&sync_cursor());
    let agent_participation_sync_key = format!(
        "{}|{}|{}|{}|{}|{}",
        selected_realm_id,
        selected_channel_value,
        selected_scope_circle.as_deref().unwrap_or_default(),
        account_sync_ready as u8,
        realm_live_epoch(),
        readable_participation_agent_ids.join(",")
    );
    let mode_accounts = participants_for_messages
        .iter()
        .filter(|p| p.is_agent)
        .filter_map(participant_mention_account)
        .collect::<Vec<_>>();
    let mode_key = {
        let store = state_store.read();
        agent_modes::AgentModeReadKey {
            base: base_url.clone(),
            authority: authority.clone(),
            realm: selected_realm_id.clone(),
            credential: token(),
            session_epoch: crate::identity::device_directory::session_cache_epoch(),
            realm_epoch: realm_live_epoch(),
            sync_ready: account_sync_ready,
            generation: store.current_generation(),
            ready: store.current_product_view_ready(&selected_realm_id),
            complete: store
                .current_product_view()
                .is_some_and(|view| view.realm_id == selected_realm_id && view.complete_cut),
            reset: store.current_reset_required(),
            head: arkret_sdk::RealmId::new(selected_realm_id.clone())
                .ok()
                .and_then(|realm_id| {
                    store
                        .verified_commit_stream_cursor(&arkret_sdk::CommitStreamRef::Realm {
                            realm_id,
                        })
                        .ok()
                        .flatten()
                }),
            accounts: mode_accounts,
        }
    };
    let interaction_modes_snapshot = agent_modes::use_agent_modes(mode_key);
    let mut public_agent_accounts = participants_for_messages
        .iter()
        .filter(|p| {
            participant_mention_account(p).is_some_and(|account| {
                interaction_modes_snapshot.get(&account)
                    == Some(&arkret_sdk::AgentInteractionMode::Public)
            })
        })
        .filter_map(participant_mention_account)
        .collect::<std::collections::BTreeSet<_>>();
    if direct_mode {
        public_agent_accounts.extend(
            participants_for_messages
                .iter()
                .filter(|participant| {
                    participant.is_agent
                        && direct_agent_is_conversation_peer(
                            &participant.roster_key(),
                            &direct_peer_id,
                            &projected_member_ids,
                        )
                })
                .filter_map(participant_mention_account),
        );
    }
    let public_agent_ids = public_agent_accounts
        .iter()
        .map(|a| arkret_sdk::ActorId::account(a.clone()).to_string())
        .collect::<std::collections::BTreeSet<_>>();
    participants.retain(|participant| {
        !participant.is_agent
            || (if direct_mode {
                direct_agent_is_conversation_peer(
                    &participant.roster_key(),
                    &direct_peer_id,
                    &projected_member_ids,
                )
            } else {
                participant_mention_account(participant)
                    .is_some_and(|a| public_agent_accounts.contains(&a))
            })
    });
    let sidecar_owned_agents =
        sidecar_owned_agent_participants(&participants_for_messages, &principal_id);
    // The source composer keeps both ordinary members and selectable owned
    // Agents. Current structured mentions choose the write audience; private
    // history neither narrows the picker nor grants public Agent participation.
    let composer_participants: Vec<_> = participants_for_messages
        .iter()
        .filter(|p| {
            !p.is_agent
                || participant_mention_account(p)
                    .is_some_and(|a| public_agent_accounts.contains(&a))
                || p.agent_metadata
                    .as_ref()
                    .is_some_and(|m| same_principal_core(&m.controller_principal_id, &principal_id))
        })
        .cloned()
        .collect();

    let presence_participants = if sidecar_mode {
        sidecar_presence_participants(&participants, &principal_id)
    } else {
        participants.clone()
    };

    let participant_ids_for_presence = presence_participant_ids(&presence_participants);
    let self_presence_actor = crate::app::SessionContext::get()
        .active_account()
        .map(|account| arkret_sdk::ActorId::account(account.authority).to_string());
    let has_remote_presence = participant_ids_for_presence
        .iter()
        .any(|id| Some(id) != self_presence_actor.as_ref());
    let presence_sync_key = format!(
        "{}|{}",
        selected_realm_id,
        participant_ids_for_presence.join(",")
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
                message.sender == principal_id
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
        SidecarDeliveryDiagnostics {
            submit,
            fanout,
            receipt,
            last_updated,
        }
    });
    let direct_mls_epoch = direct_mode
        .then(|| {
            state_store
                .read()
                .mls_checkpoint_for_effective_scope(&selected_realm_id, None)
                .map(|snapshot| snapshot.epoch.to_string())
        })
        .flatten();
    if source_suspended {
        return rsx! {};
    }
    rsx! {
        div {
            class: "{shell_class}",
            "data-testid": "chat-panel",
            "data-mls-epoch": direct_mls_epoch,
            "data-chat-mode": if direct_mode { "direct" } else { "collaboration" },
            "data-initial-sync": if shared_sync_finished { "complete" } else { "pending" },
            ChatEffects {
                controller,
                ordinary_timeline,
                timeline_basis,
                authority: authority.clone(),
                principal_id: principal_id.clone(),
                device_id: account_device_id.clone(),
                selected_realm_id: selected_realm_id.clone(),
                initial_strand_id: initial_strand_id.clone(),
                plaintext_service_id: plaintext_service_id.clone(),
                sync_cursor,
                realm_live_epoch,
                frontier_state,
                agent_participation_sync_key: agent_participation_sync_key.clone(),
                selected_scope_circle: selected_scope_circle.clone(),
                readable_participation_agent_ids: readable_participation_agent_ids.clone(),
                participant_ids_for_presence: participant_ids_for_presence.clone(),
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
                                            encrypted: channel.effective_scope(&selected_realm_id)
                                                .and_then(|scope| state_store.read().installed_scope_mls_current(&scope).activated())
                                                .unwrap_or(true),
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
                                selected: new_channel_scope,
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
                                    let actor = principal_id.clone();
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
                                        let op = match ak_ops::discussion_strand_create(
                                            &realm,
                                            &actor,
                                            &title,
                                            &category,
                                            (!summary.is_empty()).then_some(summary.as_str()),
                                            selected_scope_circle_id.as_deref(),
                                            create_card,
                                        )
                                        .and_then(|builder| builder.build_sdk_event("inkson"))
                                        {
                                            Ok(op) => op,
                                            Err(error) => {
                                                status_msg.set(format!(
                                                    "Could not create Strand: {error}"
                                                ));
                                                return;
                                            }
                                        };
                                        // The Strand is named by its own create Event, so its id
                                        // exists only once that Event is accepted. Until then this
                                        // write is known by its holder-local operation id.
                                        let api_token = token();
                                        let wait_for = active_sync_token(sync_cursor());
                                        let channel_topic = if summary.is_empty() { None } else { Some(summary) };
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        status_msg.set("Creating Strand".to_owned());
                                        controller.create_strand(
                                            base,
                                            api_token,
                                            wait_for,
                                            realm,
                                            op,
                                            StrandCreateDraft {
                                                title,
                                                category,
                                                topic: channel_topic,
                                                create_card,
                                                scope_circle: selected_scope_circle,
                                                frontier_state,
                                            },
                                        );
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
                            span { class: "muted sidecar-subtitle", "Private AI sidecar · you and eligible Agents in this Realm" }
                        }
                    }
                    if !embedded {
                    div { class: "discussion-head-actions",
                        // Start a realm-scoped call. `direct_mode` strands map
                        // to a 1:1 call; group strands open an SFU conference.
                        if crate::views::call::media_route_adapter_available() {
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
                        }
                        {
                            let request = if !sidecar_mode && selected_scope_circle.is_none() {
                                arkret_sdk::RealmId::new(selected_realm_id.clone()).ok().zip(
                                    arkret_sdk::StrandId::new(selected_channel_value.clone()).ok()
                                ).map(|(realm_id, strand_id)| arkret_sdk::StrandWatchCurrentRequestBody {
                                    realm_id, strand_id, watcher_actor_id: arkret_sdk::ActorId::account(authority.clone()),
                                })
                            } else { None };
                            let observed = (controller.strand_watch_current)();
                            let enabled = request.as_ref().zip(observed.as_ref()).is_some_and(|(request, current)| current.validate_for_request(request).is_ok())
                                && !(controller.strand_watch_pending)();
                            let explicit_level = observed.as_ref().and_then(|current| match current {
                                arkret_sdk::StrandWatchCurrentOutcome::Current { result, .. } => match result.value {
                                    arkret_sdk::StrandWatchCurrentValue::Set(value) => Some(value.level),
                                    arkret_sdk::StrandWatchCurrentValue::Cleared(()) => None,
                                },
                                arkret_sdk::StrandWatchCurrentOutcome::NeverWritten { .. } => None,
                            });
                            let label = if (controller.strand_watch_pending)() { crate::i18n::tr("chat.watch_level.pending_short") }
                                else if enabled && explicit_level.is_none() { crate::i18n::tr("chat.watch_level.default") }
                                else if enabled { crate::i18n::tr(watch_level_label_key((controller.strand_watch_level)())) }
                                else { crate::i18n::tr("chat.watch_level.unavailable_short") };
                            let tooltip = crate::i18n::tr(if enabled { "chat.watch_level.tooltip" } else if (controller.strand_watch_pending)() { "chat.watch_level.pending" } else { "chat.watch_level.unavailable" });
                            rsx! {
                                DropdownMenu {
                                    class: "watch-level-picker", "data-testid": "watch-level-picker",
                                    disabled: !enabled,
                                    open: enabled && (controller.watch_level_menu_open)(),
                                    on_open_change: move |open| {
                                        let mut menu = controller.watch_level_menu_open;
                                        menu.set(open);
                                    },
                                    DropdownMenuTrigger {
                                        class: "watch-level-toggle",
                                        "data-testid": "watch-level-toggle",
                                        title: tooltip,
                                        "aria-label": format!("{}：{}", crate::i18n::tr("chat.watch_level.title"), label),
                                        UiIcon { name: "bell" }
                                        span { class: "watch-level-toggle-label", {crate::i18n::tr("chat.watch_level.prefix")} }
                                        span { class: "watch-level-status", "{label}" }
                                        span { class: "watch-level-toggle-caret", "aria-hidden": "true", UiIcon { name: "chevron-down" } }
                                    }
                                    DropdownMenuContent {
                                        class: "watch-level-menu",
                                        "data-testid": "watch-level-menu",
                                        "aria-label": crate::i18n::tr("chat.watch_level.title"),
                                        for (index, (level, key, description)) in [
                                            (Some(arkret_sdk::StrandWatchLevel::MentionsOnly), "chat.watch_level.mentions_only", "chat.watch_level.mentions_only_description"),
                                            (Some(arkret_sdk::StrandWatchLevel::Participating), "chat.watch_level.participating", "chat.watch_level.participating_description"),
                                            (Some(arkret_sdk::StrandWatchLevel::All), "chat.watch_level.all", "chat.watch_level.all_description"),
                                            (Some(arkret_sdk::StrandWatchLevel::Muted), "chat.watch_level.muted", "chat.watch_level.muted_description"),
                                            (None, "chat.watch_level.clear", "chat.watch_level.clear_description"),
                                        ].into_iter().enumerate() {
                                            DropdownMenuItem::<Option<arkret_sdk::StrandWatchLevel>> {
                                                index,
                                                value: level,
                                                class: if explicit_level == level { "watch-level-option active" } else { "watch-level-option" },
                                                "data-watch-level": if level.is_none() { "default" } else { key.trim_start_matches("chat.watch_level.") },
                                                "aria-selected": explicit_level == level,
                                                on_select: {
                                                    let request = request.clone();
                                                    let base = base_url.clone();
                                                    move |level| {
                                                        if let Some(request) = request.clone() {
                                                            controller.set_strand_watch_level(base.clone(), token(), request, level);
                                                        }
                                                    }
                                                },
                                                span { class: "watch-level-check", "aria-hidden": "true",
                                                    if explicit_level == level { UiIcon { name: "check" } }
                                                }
                                                span { class: "watch-level-option-copy",
                                                    span { class: "watch-level-option-label", {crate::i18n::tr(key)} }
                                                    span { class: "watch-level-option-description", {crate::i18n::tr(description)} }
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

                // Offline queue banner. Visible while the browser is offline or
                // Garth still has pending chat events for this actor.
                {
                    let queued_count = queued_outbound_local_operation_ids().len();
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

                if selected_realm_pending_mls_binding && selected_channel_security_encrypted && !send_readiness_checking {
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
                div { class: "discussion-typing-slot",
                {
                    let active_typers: Vec<String> = typing_actors()
                        .into_iter()
                        .filter(|actor| Some(actor) != self_presence_actor.as_ref())
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
                }

                if direct_mode && !embedded {
                    direct_structure::DirectStructurePanel {
                        realm: selected_realm_id.clone(), base: base_url.clone(), account: authority.clone(), device: account_device_id.clone(),
                        token, selected: selected_channel, frontier: frontier_state, live_epoch: realm_live_epoch,
                        on_select: move |id| controller.select_channel(id),
                    }
                }
                if sidecar_mode && sidecar_exchange_current.is_err() {
                    div {
                        class: "event warning-banner",
                        "data-testid": "sidecar-timeline-current-pending",
                        role: "status",
                        "Private exchange history is awaiting verified Sidecar history. Original Strand messages remain available."
                    }
                }
                ChatTimeline {
                    key: "{timeline_scope_key}",
                    controller,
                    context: ChatTimelineContext {
                        embedded,
                        visible_messages: visible_timeline,
                        strand_scope_lookup: strand_scope_lookup.clone(),
                        private_sidecar_event_ids: private_sidecar_event_ids.clone(),
                        authority: authority.clone(),
                        principal_id: active_account.principal_id().clone(),
                        account_display_label: account_display_label.clone(),
                        participants: participants_for_messages.clone(),
                        selected_realm_id: selected_realm_id.clone(),
                        selected_channel_id: sidecar_session
                            .as_ref()
                            .map(|session| session.source_strand_id.clone())
                            .unwrap_or_else(|| selected_channel_value.clone()),
                        sidecar_active: sidecar_mode,
                        direct_mode,
                        device_id: account_device_id.clone(),
                        base_url: base_url.clone(),
                        focus_message_id: focus_message_id.clone(),
                        blocked_actor_ids: blocked_actor_id_set.clone(),
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
                DiscussionUsersPanel {
                    sidecar_mode,
                    right_panel,
                    sidecar_session: sidecar_session.clone(),
                    account_primary_handle: account_primary_handle.clone(),
                    sidecar_owned_agents: sidecar_owned_agents.clone(),
                    sidecar_security_label: sidecar_security_label.map(str::to_owned),
                    presence_participants: presence_participants.clone(),
                    state_store,
                    participants: participants.clone(),
                    participants_for_messages: participants_for_messages.clone(),
                    presence_labels,
                    presence_states,
                    presence_status_messages,
                    public_agent_ids: public_agent_ids.clone(),
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Settings) {
                DiscussionSettingsPanel {
                    sidecar_mode,
                    right_panel,
                    sidecar_session: sidecar_session.clone(),
                    sidecar_delivery_diagnostics: sidecar_delivery_diagnostics.clone(),
                    sidecar_security_label: sidecar_security_label.map(str::to_owned),
                    state_store,
                    selected_realm_id: selected_realm_id.clone(),
                    selected_channel_id: selected_channel_value.clone(),
                    selected_channel_category: selected_channel_category.clone(),
                    selected_channel_unread,
                    visible_message_count,
                    on_open_agent_settings: move |_| {
                        navigator.push(Route::SettingsSection {
                            section: "agents".to_owned(),
                            filter: String::new(),
                        });
                    },
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
                                    let actor = principal_id.clone();
                                    move |_| {
                                        let draft_snapshot = promote_discussion_draft.read().clone();
                                        let Some(source_id) = draft_snapshot.source_id.clone() else {
                                            return;
                                        };
                                        let title = draft_snapshot.title.trim().to_owned();
                                        // The Circle and Strand ids fall out of
                                        // the create Events, so they exist only
                                        // after the unit is authored. The
                                        // promoted indicator is therefore set
                                        // once the unit lands, not before.
                                        let steps = match crate::messaging::discussion_promote::build_promote_steps(
                                            &realm,
                                            &actor,
                                            &source_id,
                                            &title,
                                        ) {
                                            Ok(steps) => steps,
                                            Err(err) => {
                                                status_msg.set(format!(
                                                    "Private discussion creation failed: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                        promote_discussion_draft.write().close();

                                        let base = base.clone();
                                        let api_token = token();
                                        let source_id_for_rollback = source_id.clone();
                                        controller.promote_private_discussion(base, api_token, source_id_for_rollback, steps);
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
                    sidecar_route_pending,
                    embedded,
                    selected_channel_info: selected_channel_info.clone(),
                    authority: authority.clone(),
                    did: did.clone(),
                    principal_id: principal_core_id.clone(),
                    account_display_label: account_display_label.clone(),
                    participants: composer_participants.clone(),
                    selected_realm_id: selected_realm_id.clone(),
                    device_id: account_device_id.clone(),
                    selected_channel_security_encrypted,
                    selected_realm_pending_mls_binding,
                    selected_realm_pending_mls_binding_reason: selected_realm_pending_mls_binding_reason.clone(),
                    send_readiness_checking,
                    active_sidecar_session: sidecar_session.clone(),
                    sidecar_send_block_reason: sidecar_send_block_reason.clone(),
                    public_agent_ids: public_agent_ids.clone(),
                    interaction_modes: interaction_modes_snapshot.clone(),
                    mention_insert_request,
                    mentions_enabled: composer::chat_mentions_enabled(direct_mode),
                    token,
                    sync_cursor,
                    frontier_state,
                }
            }
            div { class: "discussion-status-slot",
            if !status_msg().is_empty() {
                div {
                    class: "muted discussion-status",
                    "data-testid": "chat-status",
                    role: "status",
                    "aria-live": "polite",
                    // Keep preparation errors visible when the composer has no
                    // available channel yet, including a pending private scope.
                    title: "{status_msg}",
                    "{status_msg}"
                }
            }
            }
        }
    }
}

#[cfg(test)]
mod tests;
