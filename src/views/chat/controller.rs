use arkret_wire::event_kind_str;

use super::*;

/// Closed set of shared-pin bodies, read back through their typed marker
/// payloads so the recorded `payload` stays a closed discriminated shape.
#[derive(serde::Serialize)]
#[serde(untagged)]
enum SharedPinOperationBody {
    Add(Box<arkret_sdk::PinAddPayload>),
    Remove(arkret_sdk::PinRemovePayload),
}

/// Op-log record appended once a shared-pin write is accepted; field order
/// matches the wire layout the previous `json!` literal produced.
#[derive(serde::Serialize)]
struct SharedPinOperationRecord<'a> {
    event_id: &'a str,
    kind: &'a str,
    payload: SharedPinOperationBody,
}

fn shared_pin_operation_body(
    operation: &crate::operation::LocalOperation,
) -> anyhow::Result<SharedPinOperationBody> {
    Ok(match operation.kind() {
        arkret_sdk::EventKind::PinAdd => SharedPinOperationBody::Add(Box::new(
            operation.typed_payload::<arkret_wire::event_spec::PinAdd>()?,
        )),
        arkret_sdk::EventKind::PinRemove => SharedPinOperationBody::Remove(
            operation.typed_payload::<arkret_wire::event_spec::PinRemove>()?,
        ),
        other => anyhow::bail!("unsupported shared pin kind {}", other.as_str()),
    })
}

#[derive(Clone, PartialEq)]
pub(super) struct ChatCommandContext {
    pub base_url: String,
    pub authority: arkret_sdk::AccountId,
    pub principal_id: arkret_sdk::DidCoreId,
    pub device_id: arkret_sdk::DeviceId,
    pub selected_realm_id: String,
    pub selected_channel_id: String,
    pub selected_channel_security_encrypted: bool,
    pub token: Signal<String>,
    pub sync_cursor: Signal<String>,
    pub frontier_state: Signal<String>,
}

#[derive(Clone, PartialEq)]
pub(super) struct ModerationReportDraft {
    pub realm_id: String,
    pub effective_scope: arkret_sdk::ScopeRef,
    pub target_ref: String,
    pub reason: String,
    pub description: String,
}

pub(super) enum ChatProjectionEvent {
    EnsureChannel(ChannelEntity),
    SharedPins(Vec<SharedMessagePin>),
    PrivateSaved {
        targets: std::collections::BTreeSet<String>,
        entries: std::collections::BTreeMap<String, serde_json::Value>,
    },
    Connectivity(bool),
    Typing {
        actors: Vec<String>,
        expires_at_ms: Option<i64>,
    },
    ReadCursor(String),
    OwnedAgents(std::collections::BTreeMap<String, String>),
    AgentParticipation(std::collections::BTreeMap<String, bool>),
    Presence {
        states: std::collections::BTreeMap<String, String>,
        labels: std::collections::BTreeMap<String, String>,
        status_messages: std::collections::BTreeMap<String, String>,
    },
    InitialSync {
        requested: bool,
        finished: bool,
    },
    MergeChannels(Vec<ChannelEntity>),
    MergeMessages(Vec<ChatMessage>),
    ReplaceMessages(Vec<ChatMessage>),
    ReplacePollProjection(Vec<crate::messaging::polls::PollCard>),
    AccountDisplayName(String),
}

#[derive(Clone, Copy)]
pub(super) struct ChatProjectionSink(ChatController);

impl ChatProjectionSink {
    pub fn new(controller: ChatController) -> Self {
        Self(controller)
    }

    pub fn emit(mut self, event: ChatProjectionEvent) {
        match event {
            ChatProjectionEvent::EnsureChannel(channel) => {
                // EnsureChannel runs in the route-derived effect. An observed
                // read here would subscribe that effect to user selection and
                // reset every newly selected Strand back to the route default.
                if self.0.selected_channel.peek().as_str() != channel.strand_id.as_str() {
                    self.0.selected_channel.set(channel.strand_id.clone());
                }
                if !self
                    .0
                    .channels
                    .peek()
                    .iter()
                    .any(|current| current.strand_id == channel.strand_id)
                {
                    self.0.channels.write().push(channel);
                }
            }
            ChatProjectionEvent::SharedPins(pins) => self.0.shared_pins.set(pins),
            ChatProjectionEvent::PrivateSaved { targets, entries } => {
                self.0.private_saved_targets.set(targets);
                self.0.private_saved_account_data.set(entries);
            }
            ChatProjectionEvent::Connectivity(online) => self.0.is_online.set(online),
            ChatProjectionEvent::Typing {
                actors,
                expires_at_ms,
            } => {
                self.0.typing_actors.set(actors);
                self.0.typing_next_expires_at_ms.set(expires_at_ms);
            }
            ChatProjectionEvent::ReadCursor(cursor) => self.0.latest_read_cursor.set(cursor),
            ChatProjectionEvent::OwnedAgents(agents) => self.0.owned_agent_slugs.set(agents),
            ChatProjectionEvent::AgentParticipation(visibility) => {
                self.0.agent_participation_visibility.set(visibility);
            }
            ChatProjectionEvent::Presence {
                states,
                labels,
                status_messages,
            } => {
                self.0.presence_states.set(states);
                self.0.presence_labels.set(labels);
                self.0.presence_status_messages.set(status_messages);
            }
            ChatProjectionEvent::InitialSync {
                requested,
                finished,
            } => {
                self.0.initial_sync_requested.set(requested);
                self.0.initial_sync_finished.set(finished);
            }
            ChatProjectionEvent::MergeChannels(channels) => {
                merge_channels(&mut self.0.channels.write(), channels);
            }
            ChatProjectionEvent::MergeMessages(messages) => {
                merge_chat_messages(&mut self.0.messages.write(), messages);
            }
            ChatProjectionEvent::ReplaceMessages(messages) => self.0.messages.set(messages),
            ChatProjectionEvent::ReplacePollProjection(cards) => {
                replace_poll_projection(&mut self.0.poll_cards.write(), cards);
            }
            ChatProjectionEvent::AccountDisplayName(name) => {
                self.0.account_display_name.set(name);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(super) struct ChatController {
    pub channels: Signal<Vec<ChannelEntity>>,
    pub selected_channel: Signal<String>,
    pub messages: Signal<Vec<ChatMessage>>,
    pub draft: Signal<String>,
    pub typing_throttle: crate::perf::TypingThrottle,
    pub compose_dragover: Signal<bool>,
    pub compose_upload_status: Signal<String>,
    pub shared_pins: Signal<Vec<SharedMessagePin>>,
    pub private_saved_targets: Signal<std::collections::BTreeSet<String>>,
    pub private_saved_account_data: Signal<std::collections::BTreeMap<String, serde_json::Value>>,
    pub message_context_menu: Signal<Option<String>>,
    pub moderation_report_draft: Signal<Option<ModerationReportDraft>>,
    pub moderation_report_pending: Signal<bool>,
    pub new_channel_name: Signal<String>,
    pub new_channel_topic: Signal<String>,
    pub new_channel_create_card: Signal<bool>,
    pub create_dialog_open: Signal<bool>,
    pub strand_watch_level: Signal<WatchLevel>,
    pub strand_watch_current: Signal<Option<arkret_sdk::StrandWatchCurrentOutcome>>,
    pub strand_watch_pending: Signal<bool>,
    pub strand_watch_request: Signal<u64>,
    pub watch_level_menu_open: Signal<bool>,
    pub status_msg: Signal<String>,
    /// Holder-local ids of the sends still sitting in the durable queue.
    ///
    /// Holder-local because a queued send has no accepted Message id: the
    /// Message is named by the create Event, and nothing has accepted it yet.
    pub queued_outbound_local_operation_ids: Signal<std::collections::BTreeSet<String>>,
    pub is_online: Signal<bool>,
    pub reply_to_message: Signal<Option<String>>,
    pub editing_message: Signal<Option<String>>,
    pub edit_draft: Signal<String>,
    pub redact_confirm: Signal<Option<String>>,
    pub reaction_picker: Signal<Option<String>>,
    pub initial_sync_requested: Signal<bool>,
    pub initial_sync_finished: Signal<bool>,
    pub mention_picker_state: Signal<crate::messaging::mentions::MentionPickerState>,
    pub owned_agent_slugs: Signal<std::collections::BTreeMap<String, String>>,
    pub owned_agent_sync_key_seen: Signal<String>,
    pub agent_participation_visibility: Signal<std::collections::BTreeMap<String, bool>>,
    pub agent_participation_sync_key_seen: Signal<String>,
    pub attachment_menu_open: Signal<bool>,
    pub poll_draft: Signal<Option<crate::messaging::polls::PollDraft>>,
    pub poll_cards: Signal<Vec<crate::messaging::polls::PollCard>>,
    pub typing_actors: Signal<Vec<String>>,
    pub typing_next_expires_at_ms: Signal<Option<i64>>,
    pub presence_states: Signal<std::collections::BTreeMap<String, String>>,
    pub presence_labels: Signal<std::collections::BTreeMap<String, String>>,
    pub presence_status_messages: Signal<std::collections::BTreeMap<String, String>>,
    pub presence_sync_key_seen: Signal<String>,
    pub presence_announce_key_seen: Signal<String>,
    pub presence_heartbeat_tick: Signal<u64>,
    pub promote_discussion_draft:
        Signal<crate::messaging::discussion_promote::PromoteDiscussionDraft>,
    pub promoted_targets: Signal<std::collections::BTreeMap<String, String>>,
    pub latest_read_cursor: Signal<String>,
    pub blocked_show_anyway: Signal<std::collections::BTreeSet<String>>,
    pub account_display_name: Signal<String>,
    pub track_filter: Signal<String>,
    pub left_panel_open: Signal<bool>,
    /// Circles the signed-in account may scope a new Strand to. Loaded once
    /// per (server, actor, Realm); the two keys below are the guard that keeps
    /// the load from re-triggering its own effect.
    pub eligible_circle_scopes: Signal<Vec<crate::circle::CircleSummary>>,
    pub eligible_circle_scope_request_key_seen: Signal<String>,
    pub eligible_circle_scope_request_in_flight: Signal<bool>,
    pub new_channel_scope: Signal<crate::circle::CircleScope>,
    pub sidecar_publish_open: Signal<bool>,
    pub sidecar_publish_draft: Signal<String>,
    pub sidecar_publish_pending: Signal<bool>,
    /// Member handle lookups already in flight, so a re-render does not issue
    /// the same Directory request twice.
    pub member_handle_fetching: Signal<std::collections::BTreeSet<String>>,
}

impl ChatController {
    pub fn select_channel(mut self, strand_id: String) {
        self.selected_channel.set(strand_id);
        self.message_context_menu.set(None);
        self.reaction_picker.set(None);
    }

    pub fn update_draft(mut self, draft: String) {
        self.draft.set(draft);
    }

    pub fn begin_reply(mut self, message_id: String) {
        self.reply_to_message.set(Some(message_id));
        self.editing_message.set(None);
        self.edit_draft.set(String::new());
        self.message_context_menu.set(None);
    }

    pub fn begin_edit(mut self, message_id: String, body: String) {
        self.editing_message.set(Some(message_id));
        self.edit_draft.set(body);
        self.reply_to_message.set(None);
        self.message_context_menu.set(None);
    }

    pub fn toggle_reaction_picker(mut self, message_id: String) {
        let next = (self.reaction_picker)()
            .filter(|current| current != &message_id)
            .map(|_| message_id.clone())
            .or(Some(message_id));
        if (self.reaction_picker)() == next {
            self.reaction_picker.set(None);
        } else {
            self.reaction_picker.set(next);
        }
    }

    pub fn confirm_redaction(mut self, message_id: String) {
        self.redact_confirm.set(Some(message_id));
    }

    pub fn toggle_message_menu(mut self, message_id: String) {
        let next = ((self.message_context_menu)().as_deref() != Some(message_id.as_str()))
            .then_some(message_id);
        self.message_context_menu.set(next);
    }

    pub fn close_message_menu(mut self) {
        self.message_context_menu.set(None);
    }

    pub fn begin_moderation_report(
        mut self,
        realm_id: String,
        effective_scope: arkret_sdk::ScopeRef,
        target_ref: String,
    ) {
        self.moderation_report_draft
            .set(Some(ModerationReportDraft {
                realm_id,
                effective_scope,
                target_ref,
                reason: "spam".to_owned(),
                description: String::new(),
            }));
        self.message_context_menu.set(None);
    }

    pub fn update_moderation_report_reason(mut self, reason: String) {
        if let Some(draft) = self.moderation_report_draft.write().as_mut() {
            draft.reason = reason;
        }
    }

    pub fn update_moderation_report_description(mut self, description: String) {
        if let Some(draft) = self.moderation_report_draft.write().as_mut() {
            draft.description = description;
        }
    }

    pub fn cancel_moderation_report(mut self) {
        if !(self.moderation_report_pending)() {
            self.moderation_report_draft.set(None);
        }
    }

    pub fn submit_moderation_report(mut self, context: ChatCommandContext) {
        let Some(draft) = (self.moderation_report_draft)() else {
            return;
        };
        if (self.moderation_report_pending)() {
            return;
        }
        if draft.reason == "other" && draft.description.trim().is_empty() {
            self.status_msg
                .set(crate::i18n::tr("moderation.report.other_required"));
            return;
        }
        self.moderation_report_pending.set(true);
        let base_url = context.base_url;
        let session_credential = (context.token)();
        let principal_id = context.principal_id;
        spawn(async move {
            let result = crate::transport::auth::with_event_submitter(
                &base_url,
                session_credential,
                move |submitter| async move {
                    crate::transport::moderation::report(
                        &submitter,
                        &draft.realm_id,
                        principal_id.as_str(),
                        draft.effective_scope,
                        &draft.target_ref,
                        &draft.reason,
                        Some(&draft.description),
                    )
                    .await
                },
            )
            .await;
            self.moderation_report_pending.set(false);
            match result {
                Ok(_) => {
                    self.moderation_report_draft.set(None);
                    self.status_msg
                        .set(crate::i18n::tr("moderation.report.submitted"));
                }
                Err(error) => self.status_msg.set(format!(
                    "{}: {}",
                    crate::i18n::tr("moderation.report.failed"),
                    error.display()
                )),
            }
        });
    }

    pub fn show_blocked_message(mut self, message_id: String) {
        self.blocked_show_anyway.write().insert(message_id);
    }

    pub fn close_poll(mut self, message_id: String) {
        if let Some(card) = self
            .poll_cards
            .write()
            .iter_mut()
            .find(|card| card.message_id == message_id)
        {
            card.closed = true;
        }
        self.status_msg.set("Poll closed in this view".to_owned());
    }

    pub fn update_edit_draft(mut self, content: String) {
        self.edit_draft.set(content);
    }

    pub fn cancel_edit(mut self) {
        self.editing_message.set(None);
    }

    pub fn cancel_redaction(mut self) {
        self.redact_confirm.set(None);
    }

    pub fn open_create_dialog(mut self) {
        self.create_dialog_open.set(true);
    }

    pub fn save_message_private(mut self, context: ChatCommandContext, target_ref: String) {
        if (self.private_saved_targets)().contains(&target_ref) {
            self.message_context_menu.set(None);
            return;
        }
        let namespace_key = match load_chat_productivity_namespace_key(&context.authority) {
            Ok(key) => key,
            Err(error) => {
                self.status_msg
                    .set(format!("Private save failed: {error:#}"));
                self.message_context_menu.set(None);
                return;
            }
        };
        let hlc = match crate::signing_stamp::issue_account_data_hlc(
            context.principal_id.as_str(),
            context.device_id.as_str(),
        ) {
            Ok(hlc) => hlc,
            Err(error) => {
                self.status_msg
                    .set(format!("Private save failed: {error:#}"));
                self.message_context_menu.set(None);
                return;
            }
        };
        let item = match chat_saved_account_data_item(&namespace_key, &target_ref, hlc.as_str()) {
            Ok(item) => item,
            Err(error) => {
                self.status_msg
                    .set(format!("Private save failed: {error:#}"));
                self.message_context_menu.set(None);
                return;
            }
        };
        let account_data_value =
            match crate::account_data::saved_item_account_data_value(&item.value) {
                Ok(value) => value,
                Err(error) => {
                    self.status_msg
                        .set(format!("Private save failed: {error:#}"));
                    self.message_context_menu.set(None);
                    return;
                }
            };
        let mut state_store = crate::app::SessionContext::get().state_store;
        if let Err(error) = state_store.write().stage_saved_account_data_item(&item) {
            self.status_msg
                .set(format!("Private save failed: {error:#}"));
            self.message_context_menu.set(None);
            return;
        }
        self.private_saved_targets
            .write()
            .insert(target_ref.clone());
        self.private_saved_account_data
            .write()
            .insert(item.account_data_key.clone(), account_data_value.clone());
        self.message_context_menu.set(None);
        self.status_msg
            .set(crate::i18n::tr("message.private_saved"));

        let base_url = context.base_url;
        let api_token = (context.token)();
        let wait_for = active_sync_token((context.sync_cursor)());
        let key = item.account_data_key;
        let mut status_msg = self.status_msg;
        spawn(async move {
            let result = match authed_api_with_sync(&base_url, api_token, wait_for)
                .and_then(|api| api.event_submitter())
            {
                Ok(submitter) => {
                    crate::transport::account::set_account_data(
                        &submitter,
                        &key,
                        account_data_value,
                    )
                    .await
                }
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                status_msg.set(format!(
                    "Private save stayed local: {}",
                    crate::api_error::display_user_facing(&error)
                ));
            }
        });
    }

    pub fn toggle_shared_pin(
        mut self,
        context: ChatCommandContext,
        realm_id: String,
        strand_id: String,
        target_ref: String,
    ) {
        let pin_scope = shared_pin_scope_for_message(&realm_id, &strand_id);
        let existing = (self.shared_pins)()
            .into_iter()
            .find(|pin| pin.matches_scope(&pin_scope) && pin.target_ref == target_ref);
        let removing = existing.is_some();
        let rank = existing
            .as_ref()
            .map(|pin| pin.rank.clone())
            .unwrap_or_else(next_shared_pin_rank);
        let operation = if removing {
            shared_message_pin_remove_operation(
                &realm_id,
                context.principal_id.as_str(),
                &pin_scope,
                &target_ref,
            )
        } else {
            shared_message_pin_add_operation(
                &realm_id,
                context.principal_id.as_str(),
                &pin_scope,
                &target_ref,
                &rank,
            )
        };
        let operation = match operation {
            Ok(operation) => operation,
            Err(error) => {
                self.status_msg.set(format!("Shared pin failed: {error:#}"));
                self.message_context_menu.set(None);
                return;
            }
        };
        let body = match shared_pin_operation_body(&operation) {
            Ok(body) => body,
            Err(error) => {
                self.status_msg.set(format!("Shared pin failed: {error:#}"));
                self.message_context_menu.set(None);
                return;
            }
        };
        if removing {
            self.shared_pins
                .write()
                .retain(|pin| !(pin.matches_scope(&pin_scope) && pin.target_ref == target_ref));
        } else {
            self.shared_pins.write().push(SharedMessagePin::new(
                &pin_scope,
                target_ref.clone(),
                rank,
            ));
        }
        self.message_context_menu.set(None);
        self.status_msg.set(if removing {
            crate::i18n::tr("message.shared_unpin_pending")
        } else {
            crate::i18n::tr("message.shared_pin_pending")
        });

        let mut state_store = crate::app::SessionContext::get().state_store;
        let base_url = context.base_url;
        let api_token = (context.token)();
        let wait_for = active_sync_token((context.sync_cursor)());
        let mut frontier_state = context.frontier_state;
        let mut shared_pins = self.shared_pins;
        let mut status_msg = self.status_msg;
        let rollback = existing;
        spawn(async move {
            let result = match authed_api_with_sync(&base_url, api_token, wait_for) {
                Ok(api) => match api.event_submitter() {
                    Ok(submitter) => submitter.submit_sdk_event(&operation).await,
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            };
            match result {
                Ok(submitted) => {
                    let record = match serde_json::to_value(SharedPinOperationRecord {
                        event_id: &submitted.event_id,
                        kind: operation.kind().as_str(),
                        payload: body,
                    }) {
                        Ok(record) => record,
                        Err(error) => {
                            status_msg.set(format!("Shared pin failed: {error}"));
                            return;
                        }
                    };
                    state_store.write().append_raw_operation(
                        operation.local_operation_id().to_string(),
                        Some(realm_id),
                        record,
                    );
                    frontier_state.set(submitted.event_id);
                    status_msg.set(if removing {
                        crate::i18n::tr("message.shared_unpinned")
                    } else {
                        crate::i18n::tr("message.shared_pinned")
                    });
                }
                Err(error) => {
                    if let Some(pin) = rollback {
                        shared_pins.write().push(pin);
                    } else {
                        shared_pins.write().retain(|pin| {
                            !(pin.matches_scope(&pin_scope) && pin.target_ref == target_ref)
                        });
                    }
                    status_msg.set(format!(
                        "Shared pin failed: {}",
                        crate::api_error::display_user_facing(&error)
                    ));
                }
            }
        });
    }

    pub fn add_reaction(
        mut self,
        context: ChatCommandContext,
        message_id: String,
        target_ref: String,
        emoji: String,
    ) {
        if let Some(message) = self
            .messages
            .write()
            .iter_mut()
            .find(|message| message.id == message_id)
        {
            if let Some((_, senders)) = message.reactions.iter_mut().find(|(key, _)| key == &emoji)
            {
                if !senders
                    .iter()
                    .any(|sender| sender == context.principal_id.as_str())
                {
                    senders.push(context.principal_id.to_string());
                }
            } else {
                message
                    .reactions
                    .push((emoji.clone(), vec![context.principal_id.to_string()]));
            }
        }
        let state_store = crate::app::SessionContext::get().state_store;
        let operation = match build_chat_reaction_add_operation(
            state_store,
            &context.selected_realm_id,
            &context.authority,
            context.principal_id.as_str(),
            &context.device_id,
            &target_ref,
            &emoji,
            context.selected_channel_security_encrypted,
        ) {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                self.status_msg.set(
                    "Reaction skipped: MLS state not ready for this encrypted channel".to_owned(),
                );
                self.reaction_picker.set(None);
                return;
            }
            Err(error) => {
                self.status_msg.set(format!("Reaction skipped: {error:#}"));
                self.reaction_picker.set(None);
                return;
            }
        };
        self.reaction_picker.set(None);
        let base_url = context.base_url;
        let api_token = (context.token)();
        let wait_for = active_sync_token((context.sync_cursor)());
        let mut status_msg = self.status_msg;
        spawn(async move {
            let result =
                with_authed_api_with_sync(&base_url, api_token, wait_for, |api| async move {
                    api.event_submitter()?.submit_sdk_event(&operation).await
                })
                .await;
            if let Err(error) = result {
                status_msg.set(format!("Reaction failed: {}", error.display()));
            }
        });
    }

    pub fn revise_message(
        mut self,
        context: ChatCommandContext,
        message_id: String,
        target_ref: String,
        content: String,
    ) {
        let content = content.trim().to_owned();
        if content.is_empty() {
            self.status_msg
                .set("Edit skipped: body is empty".to_owned());
            self.editing_message.set(None);
            return;
        }
        if let Some(message) = self
            .messages
            .write()
            .iter_mut()
            .find(|message| message.id == message_id)
        {
            if message.pending {
                self.status_msg.set(
                    "Wait for the current message write to settle before editing again".to_owned(),
                );
                self.editing_message.set(None);
                return;
            }
            message.revisions.push(message.body.clone());
            message.body = content.clone();
            message.content_format = Some(arkret_sdk::TextFormat::Markdown);
            message.edited = true;
            message.pending = true;
            message.failed = false;
            message.error = None;
        }
        self.editing_message.set(None);
        let base_url = context.base_url;
        let realm_id = context.selected_realm_id;
        let actor = context.principal_id;
        let api_token = (context.token)();
        let wait_for = active_sync_token((context.sync_cursor)());
        let mut messages = self.messages;
        let mut status_msg = self.status_msg;
        // Closing the edit composer unmounts its Save Button. Keep the
        // accepted-result handler with the controller that owns the message.
        dioxus::core::Runtime::current().spawn(messages.origin_scope(), async move {
            let result = match chat_content_block_for_body_with_upload(
                &base_url,
                api_token.clone(),
                wait_for.clone(),
                &realm_id,
                &content,
            )
            .await
            {
                Ok(content_block) => match chat_message_revise_operation_with_content(
                    &realm_id,
                    actor.as_str(),
                    &target_ref,
                    content_block,
                ) {
                    Ok(operation) => match authed_api_with_sync(&base_url, api_token, wait_for) {
                        Ok(api) => match api.event_submitter() {
                            Ok(submitter) => submitter.submit_sdk_event(&operation).await,
                            Err(error) => Err(error),
                        },
                        Err(error) => Err(error),
                    },
                    Err(error) => {
                        mark_message_command_failed(
                            &mut messages,
                            &message_id,
                            format!(
                                "Message update failed: {}",
                                crate::api_error::display_user_facing(&error)
                            ),
                        );
                        status_msg.set(format!(
                            "Message update failed: {}",
                            crate::api_error::display_user_facing(&error)
                        ));
                        return;
                    }
                },
                Err(error) => {
                    mark_message_command_failed(
                        &mut messages,
                        &message_id,
                        format!(
                            "Message update failed: {}",
                            crate::api_error::display_user_facing(&error)
                        ),
                    );
                    status_msg.set(format!(
                        "Message update failed: {}",
                        crate::api_error::display_user_facing(&error)
                    ));
                    return;
                }
            };
            match result {
                Ok(response) => {
                    if let Ok(event_id) = arkret_sdk::EventId::new(response.event_id.clone())
                        && let Some(message) = messages
                            .write()
                            .iter_mut()
                            .find(|message| message.id == message_id)
                    {
                        message.revision_source = Some(event_id.event_digest());
                    }
                    mark_message_command_succeeded(&mut messages, &message_id);
                    status_msg.set("Message updated".to_owned());
                }
                Err(error) => {
                    mark_message_command_failed(
                        &mut messages,
                        &message_id,
                        format!(
                            "Message update failed: {}",
                            crate::api_error::display_user_facing(&error)
                        ),
                    );
                    status_msg.set(format!(
                        "Message update failed: {}",
                        crate::api_error::display_user_facing(&error)
                    ));
                }
            }
        });
    }

    pub fn redact_message(mut self, context: ChatCommandContext, message: ChatMessage) {
        let message_id = message.id.clone();
        let target_ref = message.mutation_target_ref().to_owned();
        if let Some(found) = self
            .messages
            .write()
            .iter_mut()
            .find(|candidate| candidate.id == message_id)
        {
            found.redacted = true;
            found.body.clear();
            found.content_format = None;
            found.pending = true;
            found.failed = false;
            found.error = None;
        }
        self.redact_confirm.set(None);
        let base_url = context.base_url;
        let realm_id = context.selected_realm_id;
        let actor = context.principal_id;
        let api_token = (context.token)();
        let wait_for = active_sync_token((context.sync_cursor)());
        let mut frontier_state = context.frontier_state;
        let mut state_store = crate::app::SessionContext::get().state_store;
        let mut messages = self.messages;
        let mut status_msg = self.status_msg;
        spawn(async move {
            let operation = match chat_message_redact_operation(
                &realm_id,
                actor.as_str(),
                &target_ref,
                "user requested tombstone",
            ) {
                Ok(operation) => operation,
                Err(error) => {
                    mark_message_command_failed(
                        &mut messages,
                        &message_id,
                        format!("Message removal failed: {error:#}"),
                    );
                    status_msg.set(format!("Message removal failed: {error:#}"));
                    return;
                }
            };
            let result = match authed_api_with_sync(&base_url, api_token, wait_for) {
                Ok(api) => match api.event_submitter() {
                    Ok(submitter) => submitter.submit_sdk_event(&operation).await,
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            };
            match result {
                Ok(submitted) => {
                    // Keep the create record and append the canonical lifecycle
                    // control. Replacing the create with an unsigned synthetic
                    // tombstone made the strict projector drop the only row.
                    // The submitted operation itself contains the target and
                    // is folded immediately; the realm stream later upserts the
                    // same event id with its server-signed envelope.
                    if let Ok(payload) = serde_json::to_value(operation.intent()) {
                        state_store.write().upsert_raw_operation(
                            submitted.event_id.clone(),
                            Some(realm_id),
                            payload,
                        );
                    }
                    frontier_state.set(submitted.event_id);
                    mark_message_command_succeeded(&mut messages, &message_id);
                    status_msg.set("Message removed".to_owned());
                }
                Err(error) => {
                    mark_message_command_failed(
                        &mut messages,
                        &message_id,
                        format!(
                            "Message removal failed: {}",
                            crate::api_error::display_user_facing(&error)
                        ),
                    );
                    status_msg.set(format!(
                        "Message removal failed: {}",
                        crate::api_error::display_user_facing(&error)
                    ));
                }
            }
        });
    }

    pub fn retry_message(mut self, context: ChatCommandContext, message: ChatMessage) {
        let local_id = message.id;
        let retry_message_id = message_id_or_new_local_id(&local_id);
        if let Some(found) = self
            .messages
            .write()
            .iter_mut()
            .find(|candidate| candidate.matches_id_or_protocol(&local_id))
        {
            found.id = retry_message_id.clone();
            found.protocol_message_id = Some(retry_message_id.clone());
            found.pending = true;
            found.failed = false;
            found.error = None;
        }
        self.status_msg.set("Retrying message".to_owned());
        let state_store = crate::app::SessionContext::get().state_store;
        let mention_values = mention_nodes_to_values(&message.mentions);
        let base_url = context.base_url;
        let authority = context.authority;
        let actor = context.principal_id;
        let device_id = context.device_id;
        let encrypted = context.selected_channel_security_encrypted;
        let api_token = (context.token)();
        let wait_for = active_sync_token((context.sync_cursor)());
        let mut frontier_state = context.frontier_state;
        let mut state_store = state_store;
        let mut messages = self.messages;
        let mut status_msg = self.status_msg;
        let message_id_for_lookup = retry_message_id.clone();
        spawn(async move {
            let content = match chat_content_block_for_body_with_upload(
                &base_url,
                api_token.clone(),
                wait_for.clone(),
                &message.realm_id,
                &message.body,
            )
            .await
            {
                Ok(content) => content,
                Err(error) => {
                    mark_message_command_failed(
                        &mut messages,
                        &message_id_for_lookup,
                        format!("send failed: {error:#}"),
                    );
                    status_msg.set(format!("send failed: {error:#}"));
                    return;
                }
            };
            if encrypted {
                let content_value = match sdk_payload_value(
                    content.to_value(),
                    "chat retry encrypted content block serialize",
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        mark_message_command_failed(
                            &mut messages,
                            &message_id_for_lookup,
                            format!("send failed: {error:#}"),
                        );
                        status_msg.set(format!("send failed: {error:#}"));
                        return;
                    }
                };
                let content_bytes = match serde_json::to_vec(&content_value) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        mark_message_command_failed(
                            &mut messages,
                            &message_id_for_lookup,
                            format!("send failed: {error}"),
                        );
                        status_msg.set(format!("send failed: {error}"));
                        return;
                    }
                };
                let api = match authed_api_with_sync(&base_url, api_token.clone(), wait_for) {
                    Ok(api) => api,
                    Err(error) => {
                        mark_message_command_failed(
                            &mut messages,
                            &message_id_for_lookup,
                            format!("send failed: {error}"),
                        );
                        status_msg.set(format!("Message send failed: {error}"));
                        return;
                    }
                };
                let build = match crate::views::secure_send::build_secure_send(
                    &api,
                    state_store,
                    &message.realm_id,
                    &authority,
                    actor.as_str(),
                    &device_id,
                    &message.strand_id,
                    &retry_message_id,
                    message.reply_to.as_deref(),
                    &content_bytes,
                    None,
                    None,
                    None,
                )
                .await
                {
                    Ok(build) => build,
                    Err(error) => {
                        mark_message_command_failed(
                            &mut messages,
                            &message_id_for_lookup,
                            error.clone(),
                        );
                        status_msg.set(format!("Message send failed: {error}"));
                        return;
                    }
                };
                let local_operation_id = build.message_local_operation_id.to_string();
                let outcome = crate::views::secure_send::submit_secure_send(
                    &api,
                    state_store,
                    build,
                    &message.realm_id,
                    None,
                )
                .await;
                match outcome {
                    crate::views::secure_send::SecureSendOutcome::Sent { event_id, status } => {
                        state_store.write().mark_message_retry_replacement(
                            &message.realm_id,
                            &local_id,
                            &event_id,
                        );
                        let protocol_message_id = arkret_sdk::EventId::new(event_id.clone())
                            .ok()
                            .map(|event_id| {
                                arkret_sdk::MessageId::from_event_id(&event_id).to_string()
                            })
                            .unwrap_or_else(|| retry_message_id.clone());
                        state_store.write().append_raw_operation(
                            local_operation_id,
                            Some(message.realm_id.clone()),
                            json!({
                                "event_id": event_id.clone(),
                                "kind": event_kind_str::MESSAGE_CREATE,
                                "actor_id": actor,
                                "strand_id": message.strand_id.clone(),
                                "message_id": protocol_message_id.clone(),
                                "encrypted_content": true,
                                "status": status,
                            }),
                        );
                        state_store.write().save_private_plaintext(
                            &message.realm_id,
                            &message.strand_id,
                            &format!("message:{protocol_message_id}"),
                            &message.body,
                        );
                        if let Some(found) = messages.write().iter_mut().find(|candidate| {
                            candidate.matches_id_or_protocol(&message_id_for_lookup)
                        }) {
                            found.id = event_id.clone();
                            found.protocol_message_id = Some(protocol_message_id);
                            found.pending = false;
                            found.failed = false;
                            found.error = None;
                        }
                        frontier_state.set(event_id);
                        status_msg.set("Message sent".to_owned());
                    }
                    crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
                        mark_message_command_failed(
                            &mut messages,
                            &message_id_for_lookup,
                            message.clone(),
                        );
                        status_msg.set(format!("Message send failed: {message}"));
                    }
                    crate::views::secure_send::SecureSendOutcome::MessageAuthoringFailed {
                        failure,
                    } => {
                        present_retry_send_failure(
                            &mut messages,
                            &mut status_msg,
                            &message_id_for_lookup,
                            &failure,
                        );
                    }
                }
                return;
            }
            let content =
                match chat_content_with_mentions(&message.body, content, &message.mentions) {
                    Ok(content) => content,
                    Err(error) => {
                        mark_message_command_failed(
                            &mut messages,
                            &message_id_for_lookup,
                            format!("send failed: {error:#}"),
                        );
                        status_msg.set(format!("send failed: {error:#}"));
                        return;
                    }
                };
            let content_for_store =
                serde_json::to_value(&content).unwrap_or(serde_json::Value::Null);
            let local_operation_id =
                crate::operation::LocalOperationId::from_holder_key(retry_message_id.clone())
                    .to_string();
            let api = match crate::transport::auth::authed_api_with_sync(
                &base_url, api_token, wait_for,
            ) {
                Ok(api) => api,
                Err(error) => {
                    mark_message_command_failed(
                        &mut messages,
                        &message_id_for_lookup,
                        format!("send failed: {error:#}"),
                    );
                    status_msg.set(format!("send failed: {error:#}"));
                    return;
                }
            };
            let scope = match arkret_sdk::RealmId::new(message.realm_id.clone()) {
                Ok(realm_id) => arkret_sdk::ScopeRef::Realm { realm_id },
                Err(error) => {
                    mark_message_command_failed(
                        &mut messages,
                        &message_id_for_lookup,
                        format!("send failed: {error}"),
                    );
                    status_msg.set(format!("send failed: {error}"));
                    return;
                }
            };
            match send_ordinary_chat_message(
                &api,
                &message.realm_id,
                scope,
                &message.strand_id,
                arkret_sdk::MessageAuthoringContent::Plaintext {
                    content,
                    metadata: None,
                },
                message.reply_to.as_deref(),
                local_operation_id.clone(),
            )
            .await
            {
                Ok(submitted) => {
                    state_store.write().mark_message_retry_replacement(
                        &message.realm_id,
                        &local_id,
                        &submitted.event_id,
                    );
                    match serde_json::to_value(AcceptedChatMessageOperation {
                        event_id: &submitted.event_id,
                        kind: event_kind_str::MESSAGE_CREATE,
                        actor_id: actor.as_str(),
                        body: &message.body,
                        content: &content_for_store,
                        strand_id: &message.strand_id,
                        message_id: &retry_message_id,
                        mentions: &mention_values,
                        reply_to: message.reply_to.as_deref(),
                        status: &submitted.status,
                    }) {
                        Ok(raw_operation) => state_store.write().append_raw_operation(
                            local_operation_id.clone(),
                            Some(message.realm_id.clone()),
                            raw_operation,
                        ),
                        Err(error) => tracing::error!(
                            %error,
                            event_id = %submitted.event_id,
                            "accepted retried chat operation could not be cached"
                        ),
                    }
                    if let Some(found) = messages
                        .write()
                        .iter_mut()
                        .find(|candidate| candidate.matches_id_or_protocol(&message_id_for_lookup))
                    {
                        found.id = submitted.event_id.clone();
                        found.pending = false;
                        found.failed = false;
                        found.error = None;
                    }
                    frontier_state.set(submitted.event_id);
                    status_msg.set("Message sent".to_owned());
                }
                Err(failure) => {
                    present_retry_send_failure(
                        &mut messages,
                        &mut status_msg,
                        &message_id_for_lookup,
                        &failure,
                    );
                }
            }
        });
    }

    pub fn vote_poll(
        mut self,
        context: ChatCommandContext,
        message_id: String,
        poll_ref: arkret_sdk::MessageId,
        option_id: String,
    ) {
        self.status_msg.set("Preparing poll vote".to_owned());
        let actor = arkret_sdk::ActorId::account(context.authority.clone());
        let selected_circle = self
            .channels
            .read()
            .iter()
            .find(|channel| channel.strand_id == context.selected_channel_id)
            .and_then(|channel| channel.scope_circle.as_ref())
            .map(|scope| scope.circle_id.clone());
        let vote_check = self
            .poll_cards
            .read()
            .iter()
            .find(|card| card.message_id == message_id)
            .ok_or_else(|| anyhow::anyhow!("poll projection is unavailable"))
            .and_then(|card| {
                let realm_id = arkret_sdk::RealmId::new(context.selected_realm_id.clone())?;
                let scope = match &selected_circle {
                    Some(circle_id) => arkret_sdk::ScopeRef::Circle {
                        realm_id,
                        circle_id: arkret_sdk::CircleId::new(circle_id.clone())?,
                    },
                    None => arkret_sdk::ScopeRef::Realm { realm_id },
                };
                anyhow::ensure!(
                    card.verified_scope.as_ref() == Some(&scope),
                    "poll belongs to another Realm or Circle scope"
                );
                super::poll_submission::verified_poll_response_heads(card, &poll_ref, &actor)
            });
        let response_heads = match vote_check {
            Ok(heads) => heads,
            Err(error) => {
                self.status_msg.set(format!("Poll vote refused: {error}"));
                return;
            }
        };
        if let Some(message) = self
            .messages
            .write()
            .iter_mut()
            .find(|message| message.id == message_id)
        {
            message.pending = true;
            message.failed = false;
            message.error = None;
        }
        let protection = super::poll_submission::PollSubmissionContext {
            authority: context.authority.clone(),
            device_id: context.device_id.clone(),
            encrypted: context.selected_channel_security_encrypted,
            circle_id: self
                .channels
                .read()
                .iter()
                .find(|channel| channel.strand_id == context.selected_channel_id)
                .and_then(|channel| channel.scope_circle.as_ref())
                .map(|scope| scope.circle_id.clone()),
        };
        let state_store = crate::app::SessionContext::get().state_store;
        let base_url = context.base_url;
        let realm_id = context.selected_realm_id;
        let strand_id = context.selected_channel_id;
        let actor = context.principal_id;
        let api_token = (context.token)();
        let mut messages = self.messages;
        let mut status_msg = self.status_msg;
        // The option Button can unmount when pending/projection state changes.
        // Keep the command with the chat controller that owns these signals.
        dioxus::core::Runtime::current().spawn(messages.origin_scope(), async move {
            status_msg.set("Submitting poll vote".to_owned());
            let result =
                crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                    let operation = crate::messaging::polls::build_poll_vote_op_with_heads_scoped(
                        &realm_id,
                        actor.as_str(),
                        &strand_id,
                        protection.circle_id.as_deref(),
                        poll_ref.as_str(),
                        &[option_id],
                        response_heads.clone(),
                    )?;
                    super::poll_submission::submit_poll_operation(
                        &api,
                        state_store,
                        &protection,
                        &operation,
                        &realm_id,
                        &strand_id,
                        response_heads,
                    )
                    .await
                })
                .await;
            match result {
                Ok(_) => {
                    mark_message_command_succeeded(&mut messages, &message_id);
                    status_msg.set("Poll vote sent".to_owned());
                }
                Err(error) => {
                    let error = error.display();
                    mark_message_command_failed(
                        &mut messages,
                        &message_id,
                        format!("Poll vote failed: {error}"),
                    );
                    status_msg.set(format!("Poll vote failed: {error}"));
                }
            }
        });
    }

    /// Submit an already-built `ak.strand.create`, then adopt the Strand the
    /// server named.
    ///
    /// The Strand is named by its own create Event, so its id exists only once
    /// that Event is accepted; until then the write is known by its
    /// holder-local operation id.
    pub fn create_strand(
        mut self,
        base_url: String,
        api_token: String,
        wait_for: Option<String>,
        realm_id: String,
        operation: crate::operation::LocalOperation,
        draft: StrandCreateDraft,
    ) {
        let mut state_store = crate::app::SessionContext::get().state_store;
        let mut frontier_state = draft.frontier_state;
        spawn(async move {
            let api = match authed_api_with_sync(&base_url, api_token, wait_for) {
                Ok(api) => api,
                Err(error) => {
                    self.status_msg.set(format!("Invalid server URL: {error}"));
                    return;
                }
            };
            let submitted = match api.event_submitter() {
                Ok(sub) => sub.submit_sdk_event(&operation).await,
                Err(err) => Err(err),
            };
            let submitted = match submitted {
                Ok(submitted) => submitted,
                Err(error) => {
                    self.status_msg
                        .set(format!("Strand create failed: {error}"));
                    return;
                }
            };
            let strand_id = match arkret_sdk::EventId::new(submitted.event_id.clone()) {
                Ok(event_id) => arkret_sdk::StrandId::from_event_id(&event_id).into_string(),
                Err(error) => {
                    self.status_msg.set(format!(
                        "Strand created but its accepted id is invalid: {error}"
                    ));
                    return;
                }
            };
            self.channels.write().push(ChannelEntity {
                strand_id: strand_id.clone(),
                name: draft.title.clone(),
                kind: "discussion".to_owned(),
                category: draft.category.clone(),
                topic: draft.topic.clone(),
                unread: 0,
                is_default: false,
                is_private_sidecar: false,
                security_encrypted: None,
                scope_circle: draft.scope_circle,
            });
            self.select_channel(strand_id.clone());
            frontier_state.set(submitted.event_id.clone());
            {
                let mut store = state_store.write();
                // Keep POST /events sync_token out of the persisted
                // account-subscribe cursor; the background sync loop must
                // resume only from /account/subscribe cursors.
                store.append_raw_operation(
                    operation.local_operation_id().to_string(),
                    Some(realm_id),
                    json!({
                        "strand_id": strand_id,
                        "kind": event_kind_str::STRAND_CREATE,
                        "title": draft.title,
                        "category": draft.category,
                        "summary": draft.topic,
                        "create_card": draft.create_card,
                        "object": operation.payload()["object"].clone(),
                        "event_id": submitted.event_id,
                    }),
                );
            }
            self.status_msg.set("Strand created".to_owned());
            self.new_channel_name.set(String::new());
            self.new_channel_topic.set(String::new());
            self.new_channel_create_card.set(false);
            self.new_channel_scope
                .set(crate::circle::CircleScope::Realm);
            self.create_dialog_open.set(false);
        });
    }

    /// Observe only the exact self cell. A missing observation disables writes.
    pub fn refresh_strand_watch(
        mut self,
        base_url: String,
        api_token: String,
        request: Option<arkret_sdk::StrandWatchCurrentRequestBody>,
    ) {
        let sequence = self.strand_watch_request.peek().wrapping_add(1);
        self.strand_watch_request.set(sequence);
        self.strand_watch_current.set(None);
        self.watch_level_menu_open.set(false);
        self.strand_watch_pending.set(false);
        let Some(request) = request else {
            return;
        };
        self.strand_watch_pending.set(true);
        spawn(async move {
            let result = crate::transport::auth::with_authed_sdk_client(
                &base_url,
                api_token,
                |http| async move { crate::transport::strand_watch::read(&http, &request).await },
            )
            .await;
            if *self.strand_watch_request.peek() != sequence {
                return;
            }
            self.strand_watch_pending.set(false);
            if let Ok(current) = result {
                self.strand_watch_level.set(super::watch_level_from_wire(
                    crate::transport::strand_watch::current_level(&current),
                ));
                self.strand_watch_current.set(Some(current));
            }
        });
    }

    /// Read the real preimage immediately before signing; never fold raw watch Events.
    pub fn set_strand_watch_level(
        mut self,
        base_url: String,
        api_token: String,
        request: arkret_sdk::StrandWatchCurrentRequestBody,
        level: Option<arkret_sdk::StrandWatchLevel>,
    ) {
        if *self.strand_watch_pending.peek() || self.strand_watch_current.peek().is_none() {
            return;
        }
        let sequence = self.strand_watch_request.peek().wrapping_add(1);
        self.strand_watch_request.set(sequence);
        self.strand_watch_pending.set(true);
        self.watch_level_menu_open.set(false);
        spawn(async move {
            let result =
                crate::transport::auth::with_authed_sdk_client(
                    &base_url,
                    api_token.clone(),
                    |http| {
                        let request = request.clone();
                        async move {
                            crate::transport::strand_watch::write(&http, &request, level).await
                        }
                    },
                )
                .await;
            if *self.strand_watch_request.peek() != sequence {
                return;
            }
            self.strand_watch_pending.set(false);
            match result {
                Ok(current) => {
                    self.strand_watch_level.set(super::watch_level_from_wire(
                        crate::transport::strand_watch::current_level(&current),
                    ));
                    self.strand_watch_current.set(Some(current));
                    self.status_msg
                        .set(crate::i18n::tr("chat.watch_level.saved"));
                }
                Err(error) => {
                    let queued = crate::event_submit::is_durably_queued_error(error.inner());
                    self.status_msg.set(if queued {
                        crate::i18n::tr("chat.watch_level.queued")
                    } else {
                        crate::i18n::tr("chat.watch_level.failed")
                    });
                    if queued {
                        self.strand_watch_current.set(None);
                    } else {
                        self.refresh_strand_watch(base_url, api_token, Some(request));
                    }
                }
            }
        });
    }

    /// Publish a private sidecar message into the shared Strand.
    ///
    /// A durably queued submit is retried twice before it is reported as
    /// queued rather than failed — the Event is accepted locally either way,
    /// and telling the author it failed would invite a duplicate.
    pub fn publish_sidecar_to_shared_strand(
        mut self,
        base_url: String,
        api_token: String,
        operation: crate::operation::LocalOperation,
    ) {
        spawn(async move {
            let result =
                crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                    let submitter = api.event_submitter()?;
                    let mut attempt = 0_u8;
                    loop {
                        match submitter.submit_sdk_event(&operation).await {
                            Ok(result) => {
                                break Ok(Some(result));
                            }
                            Err(error)
                                if crate::event_submit::is_durably_queued_error(&error)
                                    && attempt < 2 =>
                            {
                                attempt += 1;
                                crate::runtime_helpers::sleep_for(
                                    std::time::Duration::from_millis(1_100),
                                )
                                .await;
                            }
                            Err(error) if crate::event_submit::is_durably_queued_error(&error) => {
                                break Ok(None);
                            }
                            Err(error) => break Err(error),
                        }
                    }
                })
                .await;
            self.sidecar_publish_pending.set(false);
            match result {
                Ok(Some(_)) => {
                    self.sidecar_publish_open.set(false);
                    self.sidecar_publish_draft.set(String::new());
                    self.status_msg.set("Published to shared Strand".to_owned());
                }
                Ok(None) => {
                    self.sidecar_publish_open.set(false);
                    self.sidecar_publish_draft.set(String::new());
                    self.status_msg
                        .set("Shared publish queued for retry".to_owned());
                }
                Err(error) => self
                    .status_msg
                    .set(format!("Shared publish failed: {}", error.display())),
            }
        });
    }

    /// Author the Circle + Strand unit that promotes a message into a private
    /// discussion.
    ///
    /// The two ids fall out of their own create Events, so the promoted
    /// indicator is only set once the whole unit lands; a half-applied promote
    /// rolls the indicator back rather than presenting itself as success.
    pub fn promote_private_discussion(
        mut self,
        base_url: String,
        api_token: String,
        source_id: String,
        steps: Vec<crate::event_submit::EventUnitStep>,
    ) {
        spawn(async move {
            let outcome =
                crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                    let submitter = api.event_submitter()?;
                    let authored = submitter.author_event_unit(steps).await?;
                    let ids = crate::messaging::discussion_promote::promote_ids(&authored)?;
                    submitter
                        .submit_signed_sdk_events_in_order(&authored)
                        .await?;
                    Ok(ids)
                })
                .await;
            match outcome {
                Ok(ids) => {
                    self.promoted_targets
                        .write()
                        .insert(source_id, ids.discussion_strand_id);
                }
                Err(err) => {
                    tracing::warn!("discussion promote failed: {}", err.display());
                    self.promoted_targets.write().remove(&source_id);
                    self.status_msg.set(format!(
                        "Private discussion creation failed: {}",
                        err.display()
                    ));
                }
            }
        });
    }
}

fn mark_message_command_succeeded(messages: &mut Signal<Vec<ChatMessage>>, message_id: &str) {
    if let Some(message) = messages
        .write()
        .iter_mut()
        .find(|message| message.matches_id_or_protocol(message_id))
    {
        message.pending = false;
        message.failed = false;
        message.error = None;
    }
}

/// Show the exact reason a retried message did not land.
///
/// A submission whose result is unknown leaves the row pending: the signed
/// bytes are durable, and inviting another retry would risk a duplicate of a
/// message that may already be accepted.
fn present_retry_send_failure(
    messages: &mut Signal<Vec<ChatMessage>>,
    status_msg: &mut Signal<String>,
    message_id: &str,
    failure: &garth::MessageAuthoringFailure,
) {
    let message = crate::i18n::tr(chat_authoring_failure_message(failure));
    if !matches!(
        failure,
        garth::MessageAuthoringFailure::SubmissionOutcomeUnknown { .. }
    ) {
        mark_message_command_failed(messages, message_id, message.clone());
    }
    status_msg.set(message);
}

fn mark_message_command_failed(
    messages: &mut Signal<Vec<ChatMessage>>,
    message_id: &str,
    error: String,
) {
    if let Some(message) = messages
        .write()
        .iter_mut()
        .find(|message| message.matches_id_or_protocol(message_id))
    {
        message.pending = false;
        message.failed = true;
        message.error = Some(error);
    }
}

/// What a Strand create still needs once the server has named the Strand.
pub(super) struct StrandCreateDraft {
    pub title: String,
    pub category: String,
    pub topic: Option<String>,
    pub create_card: bool,
    pub scope_circle: Option<StrandScopeCircle>,
    pub frontier_state: Signal<String>,
}

pub(super) fn use_chat_controller(
    selected_realm_id: &str,
    initial_strand_id: &str,
    _principal_id: &str,
) -> ChatController {
    let initial_default_channel = (!selected_realm_id.trim().is_empty())
        .then(|| discussion_channel_for_strand(initial_strand_id))
        .flatten();
    let initial_selected_channel = initial_default_channel
        .as_ref()
        .map(|channel| channel.strand_id.clone())
        .unwrap_or_default();
    let initial_channels = initial_default_channel
        .clone()
        .into_iter()
        .collect::<Vec<_>>();
    ChatController {
        channels: use_signal(move || initial_channels),
        selected_channel: use_signal(move || initial_selected_channel),
        messages: use_signal(Vec::<ChatMessage>::new),
        draft: use_signal(String::new),
        typing_throttle: crate::perf::use_typing_throttle(3_000, 4_000),
        compose_dragover: use_signal(|| false),
        compose_upload_status: use_signal(String::new),
        shared_pins: use_signal(Vec::<SharedMessagePin>::new),
        private_saved_targets: use_signal(std::collections::BTreeSet::<String>::new),
        private_saved_account_data: use_signal(
            std::collections::BTreeMap::<String, serde_json::Value>::new,
        ),
        message_context_menu: use_signal(|| None),
        moderation_report_draft: use_signal(|| None),
        moderation_report_pending: use_signal(|| false),
        new_channel_name: use_signal(String::new),
        new_channel_topic: use_signal(String::new),
        new_channel_create_card: use_signal(|| false),
        create_dialog_open: use_signal(|| false),
        strand_watch_level: use_signal(|| WatchLevel::All),
        strand_watch_current: use_signal(|| None),
        strand_watch_pending: use_signal(|| false),
        strand_watch_request: use_signal(|| 0),
        watch_level_menu_open: use_signal(|| false),
        status_msg: use_signal(String::new),
        queued_outbound_local_operation_ids: use_signal(std::collections::BTreeSet::<String>::new),
        is_online: use_signal(navigator_online),
        reply_to_message: use_signal(|| None),
        editing_message: use_signal(|| None),
        edit_draft: use_signal(String::new),
        redact_confirm: use_signal(|| None),
        reaction_picker: use_signal(|| None),
        initial_sync_requested: use_signal(|| false),
        initial_sync_finished: use_signal(|| false),
        mention_picker_state: use_signal(crate::messaging::mentions::MentionPickerState::new),
        owned_agent_slugs: use_signal(std::collections::BTreeMap::<String, String>::new),
        owned_agent_sync_key_seen: use_signal(String::new),
        agent_participation_visibility: use_signal(std::collections::BTreeMap::<String, bool>::new),
        agent_participation_sync_key_seen: use_signal(String::new),
        attachment_menu_open: use_signal(|| false),
        poll_draft: use_signal(|| None),
        poll_cards: use_signal(Vec::<crate::messaging::polls::PollCard>::new),
        typing_actors: use_signal(Vec::<String>::new),
        typing_next_expires_at_ms: use_signal(|| None),
        presence_states: use_signal(std::collections::BTreeMap::<String, String>::new),
        presence_labels: use_signal(std::collections::BTreeMap::<String, String>::new),
        presence_status_messages: use_signal(std::collections::BTreeMap::<String, String>::new),
        presence_sync_key_seen: use_signal(String::new),
        presence_announce_key_seen: use_signal(String::new),
        presence_heartbeat_tick: use_signal(|| 0),
        promote_discussion_draft: use_signal(
            crate::messaging::discussion_promote::PromoteDiscussionDraft::default,
        ),
        promoted_targets: use_signal(std::collections::BTreeMap::<String, String>::new),
        latest_read_cursor: use_signal(String::new),
        blocked_show_anyway: use_signal(std::collections::BTreeSet::<String>::new),
        account_display_name: use_signal(String::new),
        track_filter: use_signal(|| "discussion_only".to_owned()),
        left_panel_open: use_signal(|| true),
        eligible_circle_scopes: use_signal(Vec::new),
        eligible_circle_scope_request_key_seen: use_signal(String::new),
        eligible_circle_scope_request_in_flight: use_signal(|| false),
        new_channel_scope: use_signal(crate::circle::CircleScope::default),
        sidecar_publish_open: use_signal(|| false),
        sidecar_publish_draft: use_signal(String::new),
        sidecar_publish_pending: use_signal(|| false),
        member_handle_fetching: use_signal(std::collections::BTreeSet::new),
    }
}
