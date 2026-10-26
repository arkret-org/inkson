use std::rc::Rc;

use arkret_sdk::push_rule_core::WatchLevel;
use arkret_wire::event_kind_str;
use glory::prelude::*;
use serde_json::{Value, json};

use crate::circle::{CircleScope, CircleSummary};
use crate::models::EventSubmissionProgress;
use crate::operation::{ak_ops, trim_realm_id, uuid_v7};
use crate::payload::sdk_payload_value;
use crate::presentation::widgets::View;
use crate::routes::Route;
use crate::state::{ClientLocalState, LocalStateStore};
use crate::transport::TransportClient;
use crate::transport::auth::{authed_api_with_sync, with_authed_api_with_sync};
use crate::views::helpers::{MentionNode, parse_mention_nodes, short_protocol_id};

pub(crate) mod agent_modes;
mod circle_welcome;
mod composer;
mod controller;
mod direct_authority;
mod direct_structure;
mod effects;
mod message_actions;
mod message_row;
mod native;
mod page;
mod panel;
mod snapshot;
pub use message_actions::{
    MessageActionsMenuProps, MessageMenuAction, MessageMenuBoundary, MessageMenuEntry,
    message_actions_menu,
};
pub use page::{ChatPanelProps, chat_panel, page};
pub(crate) mod model;
mod poll_submission;
mod pool;
pub use pool::ChatStatePool;
mod retained_host;
mod right_panel;
mod scheduled_send_panel;
mod sidecar_projection;
mod sidecar_restore;
mod task;
mod timeline;
mod timeline_projection;
mod timeline_surface;
mod timeline_window;
pub(crate) use retained_host::retained_discussion_host;

const PRESENCE_HEARTBEAT_SECS: u64 = 25;
const PRESENCE_STARTUP_RETRY_SECS: u64 = 2;

// Private-state restoration controls sending, not whether the already
// verified public current is known. A failed probe must retain that evidence.
fn send_probe_presentation_current(
    gate: Option<&crate::mls::send_gate::MlsSendGate>,
    installed: crate::current_projection::ScopeMlsCurrent,
) -> crate::current_projection::ScopeMlsCurrent {
    match gate {
        Some(crate::mls::send_gate::MlsSendGate::Encrypted(current)) => {
            crate::current_projection::ScopeMlsCurrent::Activated(current.clone())
        }
        Some(crate::mls::send_gate::MlsSendGate::Plaintext) => {
            crate::current_projection::ScopeMlsCurrent::NotActivated
        }
        None => installed,
    }
}

#[cfg(test)]
mod send_probe_presentation_tests {
    use super::*;
    use crate::current_projection::{RealmCurrentView, ScopeMlsCurrent};

    #[test]
    fn missing_private_keys_preserve_verified_current_without_admitting_send() {
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6"
                .parse()
                .unwrap(),
        };
        let current: arkret_wire::MlsGroupValue = serde_json::from_value(json!({
            "effective_scope": scope,
            "genesis_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "current_mls_commit_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", "epoch": "4",
            "current_key_access_revision": "2", "covered_key_access_revision": "2",
            "public_tree_ref": "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460"
        })).unwrap();
        let probe = crate::mls::send_gate::decide_mls_send_gate(Ok(Some(current.clone())), None);
        assert_eq!(
            probe,
            Err(crate::mls::send_gate::MlsSendGateBlocked::LocalGroupBehind { current_epoch: 4 })
        );
        let failed_probe = probe.ok();
        assert_eq!(
            send_probe_presentation_current(
                failed_probe.as_ref(),
                ScopeMlsCurrent::Activated(current.clone())
            ),
            ScopeMlsCurrent::Activated(current)
        );
        let realm = scope.realm_id_opt().unwrap().as_str();
        let complete = RealmCurrentView::new(realm, vec![], true).unwrap();
        let partial = RealmCurrentView::new(realm, vec![], false).unwrap();
        let other = RealmCurrentView::new(
            "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            vec![],
            true,
        )
        .unwrap();
        assert_eq!(
            send_probe_presentation_current(None, complete.scope_mls_current(&scope)),
            ScopeMlsCurrent::NotActivated
        );
        assert_eq!(
            send_probe_presentation_current(None, partial.scope_mls_current(&scope)),
            ScopeMlsCurrent::Unknown
        );
        assert_eq!(
            send_probe_presentation_current(None, other.scope_mls_current(&scope)),
            ScopeMlsCurrent::Unknown
        );
    }
}

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
use controller::{
    ChatCommandContext, ChatController, ChatProjectionEvent, ChatProjectionSink, StrandCreateDraft,
};
#[cfg(test)]
pub(crate) use model::message_operations_from_events;
use model::*;
pub(crate) use model::{
    default_discussion_strand_id, verified_chat_sender_domain_for_realm,
    verify_chat_envelope_proof_for_realm,
};
use right_panel::SidecarDeliveryDiagnostics;
use timeline::*;
mod attachment_renderer;

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
    let (
        mut unknown_mode_count,
        mut unowned_private_count,
        mut missing_participant_count,
        mut selected_participant_agent_count,
    ) = (0, 0, 0, 0);
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
                selected_participant_agent_count += usize::from(target.is_some_and(|p| p.is_agent));
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
            known_mode_count = modes.len(),
            selected_participant_agent_count,
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
) -> anyhow::Result<arkret_sdk::SidecarEnsureResponseBody>
where
    F: FnMut(&'a arkret_sdk::SidecarEnsureRequestBody) -> Fut,
    Fut: std::future::Future<
            Output = arkret_sdk::http_client::Result<arkret_sdk::SidecarEnsureResponseBody>,
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
    outcome: &arkret_sdk::SidecarEnsureResponseBody,
    expected_operation_id: &arkret_sdk::ProtocolOperationId,
    expected_phase: arkret_sdk::SidecarEnsureAcceptedPhase,
    expected_sidecar_id: &arkret_sdk::SidecarId,
    expected_source_context: &arkret_sdk::SidecarContextRef,
) -> anyhow::Result<arkret_sdk::SidecarId> {
    match outcome {
        arkret_sdk::SidecarEnsureResponseBody::Accepted(accepted)
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
        arkret_sdk::SidecarEnsureResponseBody::Accepted(_) => {
            anyhow::bail!("native Sidecar accepted outcome changed its reserved binding")
        }
        arkret_sdk::SidecarEnsureResponseBody::PreparedNew(_)
        | arkret_sdk::SidecarEnsureResponseBody::PreparedExisting(_) => {
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

fn new_native_sidecar_operation_id() -> anyhow::Result<arkret_sdk::ProtocolOperationId> {
    let operation = arkret_sdk::OperationId::new_v7_at(crate::clock::now_unix_ms());
    arkret_sdk::ProtocolOperationId::new(operation.into_string()).map_err(anyhow::Error::msg)
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
    state_store: crate::presentation::SharedStateStore,
) -> anyhow::Result<Option<OwnedAgentSidecarEnsureResult>> {
    if addressed_agent_ids.is_empty() {
        return Ok(None);
    }
    let controller = authority.principal_id.clone();
    let source_realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let source_digest_suite = state_store
        .read(|value| value.station_realm_digest_suite(source_realm.as_str()))
        .ok_or_else(|| {
            anyhow::anyhow!("native Sidecar source Realm is waiting for its Station frontier")
        })?;
    let source_strand = arkret_sdk::StrandId::new(strand_id.to_owned())?;
    let mut addressed = addressed_agent_ids
        .iter()
        .map(|agent_id| crate::mls_api_helpers::principal_core_id(agent_id))
        .collect::<std::result::Result<Vec<_>, _>>()?;
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
        .read(|value| value.load_plain_local_data(&pending_key))
        .and_then(|raw| serde_json::from_str::<PendingNativeSidecarCommit>(&raw).ok())
        .filter(|pending| {
            pending.expires_at > crate::clock::now_utc()
                && pending.source_context_ref == context_ref
        });
    if pending.is_none()
        && state_store
            .read(|value| value.load_plain_local_data(&pending_key))
            .is_some()
    {
        state_store.write(|value| value.remove_plain_local_data(&pending_key));
    }
    let operation_id = match pending.as_ref() {
        Some(pending) => pending.operation_id.clone(),
        None => new_native_sidecar_operation_id()?,
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
    let ceremony_state_store = state_store.clone();
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
                    .agent_sidecar_ensure(&arkret_sdk::VerifiedSubmission::from_verified_events(prepare, &[])?)
                    .await
                    .map_err(anyhow::Error::from)?;
                ceremony_fence.check()?;
                // Device-list refresh may fence the retained key while prepare
                // is in flight. Resolve the exact active author through the
                // ordinary Event authoring path before signing either draft.
                let proof_context = crate::event_submit::EventSubmitter::new(http.clone())
                    .with_authority(ceremony_controller_account_id.clone())
                    .with_state_store(ceremony_state_store.handle())
                    .event_proof_context(source_digest_suite)
                    .await?;
                ceremony_fence.check()?;
                let idempotency_key =
                    arkret_sdk::IdempotencyKey::new(uuid_v7()).map_err(anyhow::Error::msg)?;
                match prepared {
                arkret_sdk::SidecarEnsureResponseBody::Accepted(_) => {
                    anyhow::bail!("native Sidecar prepare skipped its signed reservation ceremony")
                }
                        arkret_sdk::SidecarEnsureResponseBody::PreparedNew(
                            arkret_sdk::SidecarEnsurePreparedNewResponseBody {
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
                                let barrier = ceremony_state_store.write(|store| -> anyhow::Result<_> {
                                    store.save_plain_local_data(ceremony_pending_key.clone(),
                                        serde_json::to_string(&pending)?,
                                    );
                                    store.begin_durable_flush()
                                })?;
                                barrier.wait().await?;
                            }
                            (
                                arkret_sdk::SidecarEnsureAcceptedPhase::Commit,
                                sidecar_id,
                                request,
                                expires_at,
                            )
                        }
                        arkret_sdk::SidecarEnsureResponseBody::PreparedExisting(
                            arkret_sdk::SidecarEnsurePreparedExistingResponseBody {
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
                                let barrier = ceremony_state_store.write(|store| -> anyhow::Result<_> {
                                    store.save_plain_local_data(ceremony_pending_key.clone(),
                                        serde_json::to_string(&pending)?,
                                    );
                                    store.begin_durable_flush()
                                })?;
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
            let producer = ceremony_fence.signer.publication_context(
                &arkret_sdk::ActorId::account(ceremony_controller_account_id.clone()),
            )?;
            let verified = arkret_sdk::VerifiedSubmission::verify(request.clone(), |_| Ok(producer.clone()))?;
            let accepted = submit_frozen_sidecar_ensure(
                &request,
                expires_at,
                || ceremony_fence.check(),
                |_| http.agent_sidecar_ensure(&verified),
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
        let barrier = state_store.write(|store| -> anyhow::Result<_> {
            store.remove_plain_local_data(&pending_key);
            store.begin_durable_flush()
        })?;
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
#[path = "tests/native_harness.rs"]
mod native_harness;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "tests/sidecar_accepted_readback.rs"]
mod sidecar_accepted_readback_tests;

/// Accepted sends share the cache writer with draft and receive updates. The
/// account barrier can yield, so obtain the combined snapshot only afterwards.
async fn persist_chat_cache_after_account_barrier(
    state_store: crate::presentation::SharedStateStore,
    authority: &arkret_sdk::AccountId,
    account_ready: impl std::future::Future<Output = anyhow::Result<()>>,
    active: impl Fn() -> bool,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    account_ready.await?;
    anyhow::ensure!(
        active(),
        "accepted write belongs to a replaced account session"
    );
    let write = state_store.read(|store| -> anyhow::Result<_> {
        anyhow::ensure!(
            store.active_authority().as_ref() == Some(authority),
            "accepted write belongs to a previous account"
        );
        store.capture_e2ee_plaintext_cache_secure_write()
    })?;
    if let Some(write) = write {
        LocalStateStore::persist_captured_e2ee_cache_write_durable(secure, write).await?;
    }
    anyhow::ensure!(
        active(),
        "accepted write belongs to a replaced account session"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn submit_source_routed_sidecar_message(
    context: Rc<crate::presentation::InksonContext>,
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
    attachment_drafts: &[crate::attachments::DraftAttachment],
    mentions: &[MentionNode],
    addressed_agent_ids: &[String],
    state_store: crate::presentation::SharedStateStore,
    view: &arkret_sdk::AgentSidecarView,
) -> anyhow::Result<SourceRoutedSidecarMessageOutcome> {
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let request_epoch = crate::identity::device_directory::session_cache_epoch();
    let active_account = context.active_account;
    let active_context = context.clone();
    let request_generation = context.session_generation.get_untracked();
    let request_account = active_account.get_untracked();
    let active_store = state_store.clone();
    let active = move || {
        active_context.session_matches(request_generation, &request_account)
            && fence.check_session_identity().is_ok()
            && crate::identity::device_directory::session_cache_epoch() == request_epoch
            && active_store.read(|store| store.active_authority().as_ref() == Some(authority))
            && active_account
                .get_untracked()
                .as_ref()
                .is_some_and(|account| {
                    &account.authority == authority && &account.device_id == device_id
                })
    };
    anyhow::ensure!(
        active(),
        "private send belongs to a replaced account session"
    );
    crate::sidecar::validate_agent_sidecar_view(view)?;
    let api = crate::transport::auth::authed_api_with_sync(base_url, api_token.clone(), None)?;
    let history_pending =
        state_store.read(|value| value.has_pending_sidecar_history(source_realm_id));
    if history_pending {
        // An authenticated current may advance before its private originals.
        // Complete that cut before creating an intent or consuming the send
        // ratchet; an old fold cannot authorize the next private request.
        crate::realm_events_engine::refresh_sidecar_history(
            api.http(),
            authority,
            request_epoch,
            &view.sidecar.realm_id,
            state_store.handle(),
            &active,
        )
        .await?;
    }
    anyhow::ensure!(
        active(),
        "private send belongs to a replaced account session"
    );
    state_store.read(|store| {
        crate::sidecar::cached_sidecar_exchange_projections(store, authority, source_realm_id)
    })?;
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
        .read(|value| value.mls_checkpoint_for_scope_and_group(&effective_scope, group_id.as_str()))
        .ok_or_else(|| anyhow::anyhow!("native Sidecar MLS snapshot is unavailable"))?;
    if snapshot.group_id != group_id.as_str() {
        anyhow::bail!("native Sidecar MLS snapshot differs from its accepted group");
    }
    let mut addressed = addressed_agent_ids
        .iter()
        .map(|agent_id| crate::mls_api_helpers::principal_core_id(agent_id))
        .collect::<std::result::Result<Vec<_>, _>>()?;
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
    let content_api = crate::transport::auth::authed_api(base_url, api_token.clone())?;
    let initial_content = crate::attachments::private_message_body(
        &content_api,
        state_store.handle(),
        authority,
        device_id,
        &effective_scope,
        attached_source_strand_id,
        &crate::sidecar::sidecar_submission_intent_digest(
            attached_source_strand_id,
            body,
            addressed_agent_ids,
        ),
        body,
    )
    .await?;
    let mut content = crate::attachments::compose_draft_attachments(
        initial_content,
        attachment_drafts,
        &effective_scope,
    )?;
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
        &content_for_sidecar,
        &addressed_strings,
    );
    let Some(_submission_guard) = crate::sidecar::try_begin_sidecar_submission(
        controller_principal_id,
        attached_source_strand_id,
        &intent_digest,
    ) else {
        anyhow::bail!("this native Sidecar request is already being submitted");
    };
    let prior = state_store.read(|store| {
        crate::sidecar::load_pending_sidecar_submission(
            store,
            controller_principal_id,
            attached_source_strand_id,
            &intent_digest,
        )
    });
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
    let build = crate::views::secure_send::build_secure_send(
        &api,
        &state_store.handle(),
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
        let barrier = state_store.write(|store| -> anyhow::Result<_> {
            crate::sidecar::save_pending_sidecar_submission(store, &intent_digest, &pending)?;
            store.begin_durable_flush()
        })?;
        barrier.wait().await?;
    }
    anyhow::ensure!(
        active(),
        "private send belongs to a replaced account session"
    );
    let outcome = crate::views::secure_send::submit_secure_send(
        context,
        &api,
        &state_store.handle(),
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
        let barrier = state_store.write(|store| -> anyhow::Result<_> {
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
                store,
                controller_principal_id,
                attached_source_strand_id,
                &intent_digest,
            );
            store.begin_durable_flush()
        })?;
        persist_chat_cache_after_account_barrier(
            state_store.clone(),
            authority,
            barrier.wait(),
            &active,
            crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
        )
        .await?;
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
            state_store.handle(),
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
    context: Rc<crate::presentation::InksonContext>,
    base_url: String,
    token: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    realm: String,
    state_store: crate::presentation::SharedStateStore,
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
    if state_store
        .read(|store| {
            check_sidecar_close_authoring(
                &close_cut, &session, store, &authority, &device_id, &realm,
            )
        })
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
        let handle = state_store.handle();
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
        if state_store
            .read(|store| {
                check_sidecar_close_authoring(
                    &close_cut, &session, store, &authority, &device_id, &realm,
                )
            })
            .is_err()
        {
            return Ok(());
        }
        let mut build = crate::views::secure_send::build_sidecar_exchange_control_send(
            &state_store.handle(),
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
        state_store.read(|store| {
            check_sidecar_close_authoring(
                &close_cut, &session, store, &authority, &device_id, &realm,
            )
        })?;
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
        let plan_store = state_store.clone();
        build.message_plan =
            crate::views::secure_send::SecureWritePlan::Control(Box::new(move |accepted| {
                plan_store
                    .read(|store| {
                        check_sidecar_close_authoring(
                            &plan_cut,
                            &plan_session,
                            store,
                            &plan_authority,
                            &plan_device,
                            &plan_realm,
                        )
                    })
                    .map_err(|error| error.to_string())?;
                plan(accepted)
            }));
        match crate::views::secure_send::submit_secure_send(
            context.clone(),
            &api,
            &state_store.handle(),
            build,
            &realm,
            None,
        )
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

#[cfg(test)]
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

#[cfg(test)]
mod tests;
