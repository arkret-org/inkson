use arkret_sdk::push_rule_core::WatchLevel;
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::api_error::is_space_membership_denied_error;
use crate::audit::build_audit_ryw_receipt;
use crate::components::{
    ActorIdentityLabel, HelpTip, SecurityStateBadge, SelfAttributionBadge, UiIcon,
};
use crate::hlc::{Hlc, observe_seq};
use crate::models::SubmitEventResult;
use crate::operation::{
    OperationBuilder, ak_ops, sdk_event_local_operation_id, trim_realm_id, uuid_v7,
};
use crate::payload::sdk_payload_value;
use crate::routes::Route;
use crate::state::{ClientLocalState, LocalStateStore};
use crate::transport::TransportClient;
use crate::transport::auth::{authed_api_with_sync, with_authed_api_with_sync};
use crate::ui::button::{Button, ButtonVariant};
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
#[cfg(test)]
pub(crate) use model::message_operations_from_events;
use model::*;
use timeline::*;
use timeline_surface::{ChatTimeline, ChatTimelineContext};

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

async fn resolve_agent_selector_mentions(
    base_url: &str,
    api_token: String,
    wait_for_sync_token: Option<String>,
    body: &str,
    realm_id: &str,
    requester: &str,
    own_controller_handle: Option<&str>,
) -> Vec<MentionNode> {
    let tokens = parse_agent_selector_mention_tokens(body);
    if tokens.is_empty() {
        return Vec::new();
    }
    let Ok(api) = authed_api_with_sync(base_url, api_token, wait_for_sync_token) else {
        return Vec::new();
    };
    let mut mentions = Vec::new();
    for token in tokens {
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

async fn ensure_owned_agent_sidecar(
    base_url: &str,
    api_token: String,
    trace_id: &str,
    controller_id: &str,
    realm_id: &str,
    strand_id: &str,
    mentions: &[MentionNode],
) -> anyhow::Result<Option<arkret_sdk::AgentSidecarThreadEnsureOutcome>> {
    let addressed_agent_ids = owned_agent_ids_from_mentions(mentions, controller_id)
        .into_iter()
        .map(arkret_sdk::Did::new)
        .collect::<Result<Vec<_>, _>>()?;
    if addressed_agent_ids.is_empty() {
        return Ok(None);
    }
    let request = arkret_sdk::AgentSidecarThreadEnsureRequestBody {
        controller_id: arkret_sdk::Did::new(controller_id.to_owned())?,
        addressed_agent_ids,
        context_ref: arkret_sdk::AgentSidecarContextRef::strand(
            arkret_sdk::RealmId::new(realm_id.to_owned())?,
            arkret_sdk::StrandId::new(strand_id.to_owned())?,
        ),
    };
    tracing::info!(
        target: "sidecar",
        event = "sidecar.ensure.started",
        trace_id,
        context_ref_kind = "strand",
        attempt = 1_u8,
        addressed_agent_count = request.addressed_agent_ids.len(),
    );
    let outcome =
        crate::transport::auth::with_authed_sdk_client(base_url, api_token, |http| async move {
            http.agent_sidecar_thread_ensure(&request)
                .await
                .map_err(anyhow::Error::from)
        })
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
    tracing::info!(
        target: "sidecar",
        event = "sidecar.ensure.completed",
        trace_id,
        pending_reconciliation_count = outcome.pending_member_reconciliations.len(),
    );
    Ok(Some(outcome))
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
                        .display_name
                        .clone()
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
    body: &str,
    picker: &[crate::messaging::mentions::MentionCandidate],
    account_did: &str,
) -> Vec<MentionNode> {
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

fn apply_mention_sidecar_hashes(
    event: &mut arkret_sdk::Event,
    realm_id: &str,
    mentions: &[MentionNode],
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
    let hashes = crate::messaging::mentions::mention_sidecar_hashes(realm_id, &mention_dids);
    if let Some(content) = event
        .payload
        .get_mut("content")
        .and_then(Value::as_object_mut)
    {
        content.insert(
            "mention_sidecar_hash".to_owned(),
            Value::Array(hashes.into_iter().map(Value::String).collect()),
        );
    }
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

#[component]
pub fn ChatPanel(
    plaintext_service_id: String,
    account_did: String,
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
    /// Present only when `/direct/...` was reached through the standard
    /// Agent Sidecar ensure flow. Contact DMs continue to use direct mode
    /// without receiving Sidecar-specific membership semantics.
    #[props(default)]
    sidecar_session: Option<crate::sidecar::SidecarSession>,
    /// Optional deep-link target: when non-empty, the message with this id is
    /// scrolled into view and flashed on mount (design/route-view-ia.md §3.2).
    #[props(default)]
    focus_message_id: String,
    mention_insert_request: Option<Signal<Option<MentionInsertRequest>>>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let navigator = use_navigator();
    let controller = use_chat_controller(&selected_realm_id, &initial_strand_id, &account_did);
    let mut migrated_draft_applied_for = use_signal(String::new);
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
        outbox: chat_outbox,
        is_online,
        outbox_flushing: _,
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
        latest_read_cursor,
        blocked_show_anyway: _,
        account_display_name,
        mut track_filter,
        mut left_panel_open,
    } = controller;
    let blocked_did_set: std::collections::BTreeSet<String> = state_store
        .read()
        .client_blocklist()
        .into_iter()
        .map(|entry| entry.did)
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
    let selected_channel_name = if let Some(session) = sidecar_session.as_ref() {
        session.addressed_agent_label.clone()
    } else if embedded {
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
    let selected_channel_security_encrypted = selected_channel_info
        .as_ref()
        .and_then(|channel| channel.security_encrypted)
        .unwrap_or(selected_realm_security_encrypted);
    let selected_realm_pending_mls_binding = state_store
        .read()
        .realm_has_pending_mls_binding(&selected_realm_id);
    let sidecar_security_label = sidecar_session.as_ref().map(|session| {
        if !session.membership_ready() {
            "Reconciling access"
        } else if selected_channel_security_encrypted && selected_realm_pending_mls_binding {
            "Preparing encryption"
        } else if selected_channel_security_encrypted {
            "E2EE"
        } else {
            "Private but not E2EE"
        }
    });
    let sidecar_send_block_reason = sidecar_session.as_ref().and_then(|session| {
        if !session.membership_ready() {
            Some(format!(
                "Access is still reconciling for {} member(s). Sending is disabled until the Sidecar membership projection is ready.",
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
    let all_messages_snapshot = {
        let store = state_store.read();
        let snapshot = store.load();
        let decrypt_identity = Some((account_did.as_str(), device_id.as_str()));
        let mut folded = fold_local_state_into_chat_messages_with_sidecar(
            messages(),
            &snapshot,
            Some(&store),
            decrypt_identity,
        );
        // Account sync also carries the server-folded timeline (notably a
        // revise event rewritten into a redacted create tombstone). Merge that
        // authoritative lifecycle view after the append-only local controls so
        // representation collisions cannot leave an older revision visible.
        let server_folded = chat_messages_from_sync_realms_with_sidecar(
            &snapshot.realm_tree_projections,
            Some(&store),
            decrypt_identity,
        );
        merge_chat_messages(&mut folded, server_folded);
        folded
    };
    let visible_messages = all_messages_snapshot
        .iter()
        .filter(|msg| {
            msg.strand_id == selected_channel_value
                && (selected_realm_id.trim().is_empty() || msg.realm_id == selected_realm_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    // Dioxus may retain the child timeline across context-backed signal updates.  Key the
    // projection boundary by the actual visible message state so reaction/revision/redaction
    // folds cannot leave a memoized child rendering an older snapshot.
    let timeline_projection_key = {
        use std::hash::{Hash, Hasher};

        let mut projection = std::collections::hash_map::DefaultHasher::new();
        selected_realm_id.hash(&mut projection);
        realm_live_epoch().hash(&mut projection);
        for message in &visible_messages {
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
        format!("{:016x}", projection.finish())
    };
    let visible_moderation_appeal_prompts = moderation_appeal_prompts()
        .into_iter()
        .filter(|prompt| {
            selected_realm_id.trim().is_empty() || prompt.realm_id == selected_realm_id
        })
        .collect::<Vec<_>>();
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
    let mut participants = space_participants(participant_projection.as_ref(), &account_did);
    {
        let store = state_store.read();
        apply_cached_participant_handle_labels(
            &mut participants,
            &store,
            &selected_realm_id,
            &account_did,
            &account_display_label,
            &base_url,
        );
    }
    let own_controller_handle = participants
        .iter()
        .find(|participant| participant.is_self && !participant.is_agent)
        .and_then(mention_label_for_participant);
    // Mark agents referenced by structured mentions, then enrich any current
    // Realm member that is in the controller-owned agent inventory. The latter
    // is what makes a never-before-mentioned own agent available immediately
    // as an @me/<slug> picker row.
    {
        let mut agent_metadata = agent_metadata_from_mentions(&all_messages_snapshot);
        upsert_agent_participants(&mut participants, &agent_metadata, &account_did);
        for (agent_id, metadata) in owned_agent_metadata(
            &owned_agent_slugs(),
            &account_did,
            own_controller_handle.as_deref(),
        ) {
            agent_metadata
                .entry(agent_id)
                .and_modify(|existing| merge_agent_metadata(existing, metadata.clone()))
                .or_insert(metadata);
        }
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
    let agent_participation_sync_key = format!(
        "{}|{}|{}|{}|{}",
        selected_realm_id,
        selected_channel_value,
        selected_scope_circle.as_deref().unwrap_or_default(),
        sync_cursor(),
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
    participants.retain(|participant| {
        !participant.is_agent || public_agent_dids.contains(&participant.did)
    });

    let mut participant_dids_for_presence = participants
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

    rsx! {
        div { class: "{shell_class}", "data-testid": "chat-panel", "data-chat-mode": if direct_mode { "direct" } else { "collaboration" },
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
                                                if !op.payload["object"]
                                                    .get("fields")
                                                    .is_some_and(|fields| fields.is_object())
                                                {
                                                    op.payload["object"]["fields"] = json!({});
                                                }
                                                op.payload["object"]["fields"]["category"] =
                                                    json!(category.clone());
                                                op.payload["object"]["fields"]["has_synthesis"] =
                                                    json!(create_card);
                                                op.payload["object"]["rank"] = json!(rank.clone());
                                                if !summary.is_empty() {
                                                    op.payload["object"]["summary"] = json!(summary.clone());
                                                }
                                                if !create_card
                                                    && let Some(tracks) = op.payload["object"]["tracks"].as_object_mut()
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
                                                                security_encrypted: None,
                                                                // P3B.2.3 — the new-Strand form
                                                                // currently creates Realm-scoped
                                                                // Strands only; Circle scope
                                                                // selection arrives once the
                                                                // CircleScopePicker is mounted
                                                                // on this form.
                                                                scope_circle: None,
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
                                    r#type: "button",
                                    "data-testid": "chat-call-voice-button",
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
                                    "\u{1f4de}"
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    r#type: "button",
                                    "data-testid": "chat-call-video-button",
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
                                    "\u{1f4f9}"
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
                            let watch_disabled = strand_id_for_watch.trim().is_empty();
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
                    div { class: "sidecar-context-strip", "data-testid": "sidecar-context-strip",
                        div { class: "sidecar-context-main",
                            span { class: "muted", "Context" }
                            strong { "Realm discussion" }
                            span { class: "mono muted", "{session.source_strand_id}" }
                        }
                        a {
                            class: "button secondary",
                            href: "/chat/{session.source_realm_id}",
                            "data-testid": "sidecar-open-context",
                            "Open context"
                        }
                        div { class: "sidecar-addressed-now", "data-testid": "sidecar-addressed-now",
                            span { class: "muted", "Addressed now" }
                            strong { "{session.addressed_agent_label}" }
                            span { class: "badge", {sidecar_security_label.unwrap_or("Opening")} }
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
                    } else if !selected_channel_security_encrypted {
                        div { class: "event warning-banner", "data-testid": "sidecar-plaintext-disclosure", role: "status",
                            "This Sidecar is isolated by membership, delivery, and query permissions. Messages are not end-to-end encrypted."
                        }
                    }
                }

                // Offline outbox banner. Visible while the browser is offline
                // or the queue is non-empty so the user knows sends are parked
                // and will flush on reconnect (sync/offline-conflict).
                {
                    let queued_count = chat_outbox().len();
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
                        if !embedded || !pinned_view.is_empty() {
                            div {
                                class: "pinned-bar",
                                "data-testid": "pinned-bar",
                                "data-source": "shared-event",
                                "data-permission": "ak.pin.add ak.pin.remove",
                                if pinned_view.is_empty() {
                                    span {
                                        class: "pinned-bar-empty",
                                        "data-testid": "pinned-bar-empty",
                                        {crate::i18n::tr("pinned_bar.empty")}
                                    }
                                } else {
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
                }

                if selected_realm_pending_mls_binding && selected_channel_security_encrypted {
                    div {
                        class: "event warning-banner",
                        "data-testid": "epoch-update-required-banner",
                        role: "alert",
                        "epoch_update_required: membership frontier changed; MLS Remove commit required"
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
                    key: "{timeline_projection_key}",
                    controller,
                    context: ChatTimelineContext {
                        embedded,
                        visible_messages: visible_messages.clone(),
                        visible_moderation_appeal_prompts: visible_moderation_appeal_prompts.clone(),
                        strand_scope_lookup: strand_scope_lookup.clone(),
                        account_did: account_did.clone(),
                        account_display_label: account_display_label.clone(),
                        participants: participants_for_messages.clone(),
                        selected_realm_id: selected_realm_id.clone(),
                        selected_channel_id: selected_channel_value.clone(),
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
                                div { strong { "You" } span { class: "muted", "Controller" } }
                                span { class: "badge success", "Active" }
                            }
                            for (index, agent_id) in session.addressed_agent_ids.iter().enumerate() {
                                div { class: "sidecar-access-row", key: "{agent_id}",
                                    div {
                                        strong {
                                            if index == 0 { "{session.addressed_agent_label}" } else { "Personal agent" }
                                        }
                                        span { class: "muted mono", "{agent_id}" }
                                    }
                                    span { class: "badge", "Addressed now" }
                                }
                            }
                            div { class: "event info",
                                "This is the currently addressed set. The Sidecar Circle can also include other eligible personal agents; Inkson does not present this list as a 1:1 membership boundary."
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
                            for participant in &participants {
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
                    if let Some(session) = sidecar_session.as_ref() {
                        div { class: "discussion-detail-section sidecar-diagnostics-section", "data-testid": "sidecar-connection-details",
                            div { class: "detail-row", span { "Trace ID" } strong { class: "mono", "{session.trace_id}" } }
                            div { class: "detail-row", span { "Ensure" } strong { "Complete" } }
                            div { class: "detail-row", span { "Circle membership" } strong {
                                if session.membership_ready() { "Complete" } else { "Reconciling" }
                            } }
                            div { class: "detail-row", span { "Encryption" } strong { {sidecar_security_label.unwrap_or("Opening")} } }
                            div { class: "detail-row", span { "Message submit" } strong { "Not started" } }
                            div { class: "detail-row", span { "Notification fanout" } strong { "Not started" } }
                            div { class: "detail-row", span { "Agent receipt" } strong { "Not received" } }
                            div { class: "detail-row", span { "Last updated" } strong { {session.opened_at.format("%H:%M:%S").to_string()} } }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "sidecar-copy-diagnostics",
                                    onclick: {
                                        let summary = session.diagnostic_summary(
                                            sidecar_security_label.unwrap_or("Opening"),
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

            // G3.Y2 — read-receipt marker bar. A horizontal divider
            // sealed at the highest event id we've sent a
            // `ak.read_cursor.advance` for; renders only when we have one. The
            // `ak.read_cursor.advanceessage list so users can see the
            // "everyone read up to here" seal without scrolling
            // around. The marker itself is actor-private — see
            // discovery/read-receipts.md §3.1.
            if !embedded && !latest_read_cursor().is_empty() {
                {
                    let latest_read_cursor_value = latest_read_cursor();
                    let latest_read_cursor_label = short_protocol_id(&latest_read_cursor_value);
                    rsx! {
                        div {
                            class: "read-receipt-marker-bar",
                            "data-testid": "read-receipt-marker-bar",
                            "data-up-to-event-id": "{latest_read_cursor_value}",
                            span { "Read up to " }
                            span { class: "mono", title: "{latest_read_cursor_value}", "{latest_read_cursor_label}" }
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
                    participants: participants_for_messages.clone(),
                    selected_realm_id: selected_realm_id.clone(),
                    device_id: device_id.clone(),
                    plaintext_service_id: plaintext_service_id.clone(),
                    selected_channel_security_encrypted,
                    selected_realm_pending_mls_binding,
                    sidecar_send_block_reason: sidecar_send_block_reason.clone(),
                    public_agent_dids: public_agent_dids.clone(),
                    own_controller_handle: own_controller_handle.clone(),
                    mention_insert_request,
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
