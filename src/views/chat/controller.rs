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

#[derive(Clone)]
pub(super) struct WatchRefreshTarget {
    base_url: String,
    credential: String,
    session: crate::transport::auth::AuthoringSessionFence,
    request: arkret_sdk::StrandWatchCurrentRequestBody,
}

impl PartialEq for WatchRefreshTarget {
    fn eq(&self, other: &Self) -> bool {
        self.base_url == other.base_url
            && self.credential == other.credential
            && self.request == other.request
            && self.session.same_session_identity(&other.session)
    }
}

impl WatchRefreshTarget {
    fn capture(
        base_url: String,
        credential: String,
        request: arkret_sdk::StrandWatchCurrentRequestBody,
    ) -> Option<Self> {
        let session = crate::transport::auth::AuthoringSessionFence::capture().ok()?;
        let account = request.watcher_actor_id.as_account_id()?;
        if !session.belongs_to_account(account) || session.check_session_identity().is_err() {
            return None;
        }
        Some(Self {
            base_url,
            credential,
            session,
            request,
        })
    }
}

/// Read coalescing and write ownership are independent. A live notification
/// may supersede a read, but cannot retire a same-session write or release it.
#[derive(Clone, PartialEq)]
pub(super) struct WatchRefreshQueue<T = WatchRefreshTarget> {
    latest: Option<(u64, T)>,
    running: bool,
    publication: u64,
    next_write: u64,
    write: Option<(u64, T)>,
}

impl<T> Default for WatchRefreshQueue<T> {
    fn default() -> Self {
        Self {
            latest: None,
            running: false,
            publication: 0,
            next_write: 0,
            write: None,
        }
    }
}

impl<T: Clone + PartialEq> WatchRefreshQueue<T> {
    fn target_changed(&self, target: Option<&T>) -> bool {
        self.latest.as_ref().map(|(_, target)| target) != target
    }

    fn enqueue(&mut self, target: Option<(u64, T)>) -> bool {
        if self.target_changed(target.as_ref().map(|(_, target)| target)) {
            self.publication = self.publication.wrapping_add(1);
            self.write = None;
        }
        self.latest = target;
        if self.running || self.latest.is_none() || self.write.is_some() {
            return false;
        }
        self.running = true;
        true
    }

    fn read_owns_target(&self, publication: u64, target: &T) -> bool {
        self.write.is_none()
            && self.publication == publication
            && !self.target_changed(Some(target))
    }

    fn may_publish(&self, sequence: u64, publication: u64, target: &T) -> bool {
        self.read_owns_target(publication, target)
            && self
                .latest
                .as_ref()
                .is_some_and(|(latest, _)| *latest == sequence)
    }

    fn may_retain_presentation(
        &self,
        target: Option<&T>,
        valid_display: bool,
        queued: bool,
    ) -> bool {
        target.is_some() && !self.target_changed(target) && (valid_display || queued)
    }

    fn pending(&self, has_observation: bool, queued: bool) -> bool {
        self.write.is_some() || (self.latest.is_some() && !has_observation && !queued)
    }

    fn finish_read(&mut self) -> bool {
        self.running = false;
        self.write.is_some()
    }

    fn begin_write(&mut self, target: &T) -> Option<u64> {
        if self.write.is_some() || self.target_changed(Some(target)) {
            return None;
        }
        self.next_write = self.next_write.wrapping_add(1);
        self.publication = self.publication.wrapping_add(1);
        self.write = Some((self.next_write, target.clone()));
        Some(self.next_write)
    }

    fn finish_write(&mut self, ticket: u64, target: &T) -> bool {
        if self
            .write
            .as_ref()
            .is_none_or(|(active, value)| *active != ticket || value != target)
        {
            return false;
        }
        self.write = None;
        self.publication = self.publication.wrapping_add(1);
        !self.target_changed(Some(target))
    }
}

fn watch_read_retry_delay(
    error: &anyhow::Error,
    attempts: u32,
    backoff: &mut garth::RetrySchedule,
) -> Option<std::time::Duration> {
    if attempts >= 3 {
        return None;
    }
    let (status, problem) = crate::api_error::api_error_status_and_envelope(error)?;
    if !(status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        && matches!(
            problem.code(),
            "revision_unavailable" | "temporarily_unavailable"
        ))
        && !(status == reqwest::StatusCode::TOO_MANY_REQUESTS && problem.code() == "rate_limited")
    {
        return None;
    }
    Some(
        backoff.next_delay_with_hint(
            problem
                .retry_after_ms()
                .map(std::time::Duration::from_millis),
        ),
    )
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

#[derive(Clone)]
pub(super) struct ChatCommandContext {
    pub base_url: String,
    pub authority: arkret_sdk::AccountId,
    pub principal_id: arkret_sdk::DidCoreId,
    pub device_id: arkret_sdk::DeviceId,
    pub selected_realm_id: String,
    pub selected_channel_id: String,
    pub selected_channel_security_encrypted: bool,
    pub token: Cage<String>,
    pub frontier_state: Cage<String>,
    pub known_agent_accounts: std::collections::BTreeSet<arkret_sdk::AccountId>,
    pub private_agent_scope: bool,
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

    pub fn emit(self, event: ChatProjectionEvent) {
        match event {
            ChatProjectionEvent::EnsureChannel(channel) => {
                // EnsureChannel runs in the route-derived effect. An observed
                // read here would subscribe that effect to user selection and
                // reset every newly selected Strand back to the route default.
                if self.0.selected_channel.get_untracked().as_str() != channel.strand_id.as_str() {
                    {
                        let next_value = channel.strand_id.clone();
                        self.0.selected_channel.revise(|value| *value = next_value);
                    };
                }
                if !self
                    .0
                    .channels
                    .get_untracked()
                    .iter()
                    .any(|current| current.strand_id == channel.strand_id)
                {
                    self.0.channels.revise(|value| value.push(channel));
                }
            }
            ChatProjectionEvent::SharedPins(pins) => {
                let next_value = pins;
                self.0.shared_pins.revise(|value| *value = next_value);
            }
            ChatProjectionEvent::PrivateSaved { targets, entries } => {
                {
                    let next_value = targets;
                    self.0
                        .private_saved_targets
                        .revise(|value| *value = next_value);
                };
                {
                    let next_value = entries;
                    self.0
                        .private_saved_account_data
                        .revise(|value| *value = next_value);
                };
            }
            ChatProjectionEvent::Connectivity(online) => {
                let next_value = online;
                self.0.is_online.revise(|value| *value = next_value);
            }
            ChatProjectionEvent::Typing {
                actors,
                expires_at_ms,
            } => {
                {
                    let next_value = actors;
                    self.0.typing_actors.revise(|value| *value = next_value);
                };
                {
                    let next_value = expires_at_ms;
                    self.0
                        .typing_next_expires_at_ms
                        .revise(|value| *value = next_value);
                };
            }
            ChatProjectionEvent::ReadCursor(cursor) => {
                let next_value = cursor;
                self.0
                    .latest_read_cursor
                    .revise(|value| *value = next_value);
            }
            ChatProjectionEvent::OwnedAgents(agents) => {
                let next_value = agents;
                self.0.owned_agent_slugs.revise(|value| *value = next_value);
            }
            ChatProjectionEvent::AgentParticipation(visibility) => {
                {
                    let next_value = visibility;
                    self.0
                        .agent_participation_visibility
                        .revise(|value| *value = next_value);
                };
            }
            ChatProjectionEvent::Presence {
                states,
                labels,
                status_messages,
            } => {
                {
                    let next_value = states;
                    self.0.presence_states.revise(|value| *value = next_value);
                };
                {
                    let next_value = labels;
                    self.0.presence_labels.revise(|value| *value = next_value);
                };
                {
                    let next_value = status_messages;
                    self.0
                        .presence_status_messages
                        .revise(|value| *value = next_value);
                };
            }
            ChatProjectionEvent::InitialSync {
                requested,
                finished,
            } => {
                {
                    let next_value = requested;
                    self.0
                        .initial_sync_requested
                        .revise(|value| *value = next_value);
                };
                {
                    let next_value = finished;
                    self.0
                        .initial_sync_finished
                        .revise(|value| *value = next_value);
                };
            }
            ChatProjectionEvent::MergeChannels(channels) => {
                self.0
                    .channels
                    .revise(|value| merge_channels(value, channels));
            }
            ChatProjectionEvent::MergeMessages(messages) => {
                self.0
                    .messages
                    .revise(|value| merge_chat_messages(value, messages));
            }
            ChatProjectionEvent::ReplaceMessages(messages) => {
                let next_value = messages;
                self.0.messages.revise(|value| *value = next_value);
            }
            ChatProjectionEvent::ReplacePollProjection(cards) => {
                self.0
                    .poll_cards
                    .revise(|value| replace_poll_projection(value, cards));
            }
            ChatProjectionEvent::AccountDisplayName(name) => {
                {
                    let next_value = name;
                    self.0
                        .account_display_name
                        .revise(|value| *value = next_value);
                };
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct ChatController {
    pub channels: Cage<Vec<ChannelEntity>>,
    pub selected_channel: Cage<String>,
    pub messages: Cage<Vec<ChatMessage>>,
    pub draft: Cage<String>,
    pub draft_storage: Cage<&'static str>,
    pub draft_saved: Cage<String>,
    pub pending_drafts: Cage<std::collections::BTreeMap<String, String>>,
    pub typing_throttle: crate::perf::TypingThrottle,
    pub compose_dragover: Cage<bool>,
    pub compose_upload_status: Cage<String>,
    pub attachments: Cage<Vec<crate::attachments::DraftAttachment>>,
    pub attachment_target_key: Cage<String>,
    pub attachment_target_revision: Cage<u64>,
    pub attachment_upload_revision: Cage<u64>,
    pub selection_revision: Cage<u64>,
    pub shared_pins: Cage<Vec<SharedMessagePin>>,
    pub private_saved_targets: Cage<std::collections::BTreeSet<String>>,
    pub private_saved_account_data: Cage<std::collections::BTreeMap<String, serde_json::Value>>,
    pub message_context_menu: Cage<Option<String>>,
    pub moderation_report_draft: Cage<Option<ModerationReportDraft>>,
    pub moderation_report_pending: Cage<bool>,
    pub new_channel_name: Cage<String>,
    pub new_channel_topic: Cage<String>,
    pub new_channel_create_card: Cage<bool>,
    pub create_dialog_open: Cage<bool>,
    pub strand_watch_level: Cage<WatchLevel>,
    pub strand_watch_current: Cage<Option<arkret_sdk::StrandWatchCurrentResponseBody>>,
    pub strand_watch_pending: Cage<bool>,
    pub strand_watch_queued: Cage<bool>,
    pub strand_watch_request: Cage<u64>,
    pub strand_watch_refresh: Cage<WatchRefreshQueue>,
    pub watch_level_menu_open: Cage<bool>,
    pub status_msg: Cage<String>,
    /// Holder-local ids of the sends still sitting in the durable queue.
    ///
    /// Holder-local because a queued send has no accepted Message id: the
    /// Message is named by the create Event, and nothing has accepted it yet.
    pub queued_outbound_local_operation_ids: Cage<std::collections::BTreeSet<String>>,
    pub is_online: Cage<bool>,
    pub reply_to_message: Cage<Option<String>>,
    pub editing_message: Cage<Option<String>>,
    pub edit_draft: Cage<String>,
    pub redact_confirm: Cage<Option<String>>,
    pub reaction_picker: Cage<Option<String>>,
    pub initial_sync_requested: Cage<bool>,
    pub initial_sync_finished: Cage<bool>,
    pub mention_picker_state: Cage<crate::messaging::mentions::MentionPickerState>,
    pub owned_agent_slugs: Cage<std::collections::BTreeMap<String, String>>,
    pub owned_agent_sync_key_seen: Cage<String>,
    pub agent_participation_visibility: Cage<std::collections::BTreeMap<String, bool>>,
    pub agent_participation_sync_key_seen: Cage<String>,
    pub attachment_menu_open: Cage<bool>,
    pub poll_draft: Cage<Option<crate::messaging::polls::PollDraft>>,
    pub poll_cards: Cage<Vec<crate::messaging::polls::PollCard>>,
    pub typing_actors: Cage<Vec<String>>,
    pub typing_next_expires_at_ms: Cage<Option<i64>>,
    pub presence_states: Cage<std::collections::BTreeMap<String, String>>,
    pub presence_labels: Cage<std::collections::BTreeMap<String, String>>,
    pub presence_status_messages: Cage<std::collections::BTreeMap<String, String>>,
    pub presence_sync_key_seen: Cage<String>,
    pub presence_announce_key_seen: Cage<String>,
    pub presence_heartbeat_tick: Cage<u64>,
    pub promote_discussion_draft:
        Cage<crate::messaging::discussion_promote::PromoteDiscussionDraft>,
    pub promoted_targets: Cage<std::collections::BTreeMap<String, String>>,
    pub latest_read_cursor: Cage<String>,
    pub blocked_show_anyway: Cage<std::collections::BTreeSet<String>>,
    pub account_display_name: Cage<String>,
    pub track_filter: Cage<String>,
    pub left_panel_open: Cage<bool>,
    /// Circles the signed-in account may scope a new Strand to. Loaded once
    /// per (server, actor, Realm); the two keys below are the guard that keeps
    /// the load from re-triggering its own effect.
    pub eligible_circle_scopes: Cage<Vec<crate::circle::CircleSummary>>,
    pub eligible_circle_scope_request_key_seen: Cage<String>,
    pub eligible_circle_scope_request_in_flight: Cage<bool>,
    pub new_channel_scope: Cage<crate::circle::CircleScope>,
    pub sidecar_send_pending: Cage<bool>,
    /// Member handle lookups already in flight, so a re-render does not issue
    /// the same Directory request twice.
    pub member_handle_fetching: Cage<std::collections::BTreeSet<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CommonCoordinate<T> {
    Unselected,
    Typed(T),
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CommonTarget {
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    realm: CommonCoordinate<arkret_sdk::RealmId>,
    initial_strand: CommonCoordinate<arkret_sdk::StrandId>,
}
impl CommonTarget {
    fn new(
        authority: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        realm: &str,
        strand: &str,
    ) -> Self {
        let realm = if realm.trim().is_empty() {
            CommonCoordinate::Unselected
        } else {
            match arkret_sdk::RealmId::new(realm.to_owned()) {
                Ok(id) => CommonCoordinate::Typed(id),
                Err(_) => CommonCoordinate::Invalid(realm.to_owned()),
            }
        };
        let initial_strand = if strand.trim().is_empty() {
            CommonCoordinate::Unselected
        } else {
            match arkret_sdk::StrandId::new(strand.trim().to_owned()) {
                Ok(id) => CommonCoordinate::Typed(id),
                Err(_) => CommonCoordinate::Invalid(strand.to_owned()),
            }
        };
        Self {
            authority: authority.clone(),
            device_id: device.clone(),
            realm,
            initial_strand,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct CachedChatController {
    pub(super) controller: ChatController,
    pub(super) revision: u64,
}

impl ChatController {
    fn command_store(self) -> Option<crate::presentation::SharedStateStore> {
        match crate::presentation::require_current_context() {
            Ok(context) => Some(context.state_store.clone()),
            Err(_) => {
                let _ = self
                    .status_msg
                    .try_revise(|status| *status = "The chat window is unavailable.".into());
                None
            }
        }
    }

    /// Retire operational projections after the pool fences and cancels work.
    /// Keep the allocated handles and the separately pooled composer drafts.
    pub(super) fn retire_common_session(self) {
        macro_rules! clear { ($($field:ident),+ $(,)?) => { $(let _ = self.$field.try_revise(|value| value.clear());)+ }; }
        macro_rules! set {
            ($field:ident, $next:expr) => {
                let _ = self.$field.try_revise(|value| *value = $next);
            };
        }
        clear!(
            channels,
            selected_channel,
            messages,
            shared_pins,
            private_saved_targets,
            private_saved_account_data,
            new_channel_name,
            new_channel_topic,
            queued_outbound_local_operation_ids,
            owned_agent_slugs,
            owned_agent_sync_key_seen,
            agent_participation_visibility,
            agent_participation_sync_key_seen,
            poll_cards,
            typing_actors,
            presence_states,
            presence_labels,
            presence_status_messages,
            presence_sync_key_seen,
            presence_announce_key_seen,
            promoted_targets,
            blocked_show_anyway,
            account_display_name,
            eligible_circle_scopes,
            eligible_circle_scope_request_key_seen,
            member_handle_fetching
        );
        set!(new_channel_create_card, false);
        set!(create_dialog_open, false);
        set!(strand_watch_level, WatchLevel::All);
        set!(strand_watch_current, None);
        set!(strand_watch_pending, false);
        set!(strand_watch_queued, false);
        set!(strand_watch_refresh, WatchRefreshQueue::default());
        set!(watch_level_menu_open, false);
        set!(is_online, navigator_online());
        set!(initial_sync_requested, false);
        set!(initial_sync_finished, false);
        set!(typing_next_expires_at_ms, None);
        set!(
            promote_discussion_draft,
            crate::messaging::discussion_promote::PromoteDiscussionDraft::default()
        );
        set!(track_filter, "discussion_only".to_owned());
        set!(left_panel_open, true);
        set!(eligible_circle_scope_request_in_flight, false);
        set!(new_channel_scope, crate::circle::CircleScope::default());
        set!(sidecar_send_pending, false);
        let _ = self
            .selection_revision
            .try_revise(|value| *value = value.wrapping_add(1));
        let _ = self
            .strand_watch_request
            .try_revise(|value| *value = value.wrapping_add(1));
        let _ = self
            .presence_heartbeat_tick
            .try_revise(|value| *value = value.wrapping_add(1));
        self.typing_throttle.retire_session();
    }

    pub(super) fn for_strand(
        mut self,
        context: &Rc<crate::presentation::InksonContext>,
        authority: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        realm: &str,
        strand: &str,
    ) -> glory::ui::Result<Self> {
        let composer = composer_state(
            context,
            ComposerTarget {
                authority: authority.clone(),
                device_id: device.clone(),
                realm_id: realm.to_owned(),
                strand_id: strand.to_owned(),
            },
        )?;
        self.draft = composer.draft;
        self.draft_storage = composer.draft_storage;
        self.draft_saved = composer.draft_saved;
        self.pending_drafts = composer.pending_drafts;
        self.reply_to_message = composer.reply_to_message;
        self.editing_message = composer.editing_message;
        self.edit_draft = composer.edit_draft;
        self.compose_dragover = composer.compose_dragover;
        self.compose_upload_status = composer.compose_upload_status;
        self.attachments = composer.attachments;
        self.attachment_target_key = composer.attachment_target_key;
        self.attachment_target_revision = composer.attachment_target_revision;
        self.attachment_upload_revision = composer.attachment_upload_revision;
        self.message_context_menu = composer.message_context_menu;
        self.moderation_report_draft = composer.moderation_report_draft;
        self.moderation_report_pending = composer.moderation_report_pending;
        self.status_msg = composer.status_msg;
        self.redact_confirm = composer.redact_confirm;
        self.reaction_picker = composer.reaction_picker;
        self.mention_picker_state = composer.mention_picker_state;
        self.attachment_menu_open = composer.attachment_menu_open;
        self.poll_draft = composer.poll_draft;
        self.latest_read_cursor = composer.latest_read_cursor;
        Ok(self)
    }

    pub fn select_channel(self, strand_id: String) {
        if self.selected_channel.get_untracked() != strand_id {
            let next = self.selection_revision.get_untracked().wrapping_add(1);
            {
                let next_value = next;
                self.selection_revision.revise(|value| *value = next_value);
            };
        }
        {
            let next_value = strand_id;
            self.selected_channel.revise(|value| *value = next_value);
        };
        {
            let next_value = None;
            self.message_context_menu
                .revise(|value| *value = next_value);
        };
        {
            let next_value = None;
            self.reaction_picker.revise(|value| *value = next_value);
        };
    }

    pub fn draft_storage_status(self) -> &'static str {
        let status = self.draft_storage.get();
        let draft = self.draft.get();
        if status == "saved"
            && (self.draft_saved.get() != draft
                || (draft.is_empty() && !self.pending_drafts.get().is_empty()))
        {
            "saving"
        } else {
            status
        }
    }

    pub fn update_draft(self, draft: String) {
        if self.draft.get_untracked() != draft {
            let next = self
                .attachment_target_revision
                .get_untracked()
                .wrapping_add(1);
            {
                let next_value = next;
                self.attachment_target_revision
                    .revise(|value| *value = next_value);
            };
        }
        {
            let next_value = draft;
            self.draft.revise(|value| *value = next_value);
        };
    }

    pub fn begin_reply(self, message_id: String) {
        {
            let next_value = Some(message_id);
            self.reply_to_message.revise(|value| *value = next_value);
        };
        {
            let next_value = None;
            self.editing_message.revise(|value| *value = next_value);
        };
        {
            let next_value = String::new();
            self.edit_draft.revise(|value| *value = next_value);
        };
        {
            let next_value = None;
            self.message_context_menu
                .revise(|value| *value = next_value);
        };
    }

    pub fn begin_edit(self, message_id: String, body: String) {
        {
            let next_value = Some(message_id);
            self.editing_message.revise(|value| *value = next_value);
        };
        {
            let next_value = body;
            self.edit_draft.revise(|value| *value = next_value);
        };
        {
            let next_value = None;
            self.reply_to_message.revise(|value| *value = next_value);
        };
        {
            let next_value = None;
            self.message_context_menu
                .revise(|value| *value = next_value);
        };
    }

    pub fn toggle_reaction_picker(self, message_id: String) {
        let next = self
            .reaction_picker
            .get()
            .filter(|current| current != &message_id)
            .map(|_| message_id.clone())
            .or(Some(message_id));
        if self.reaction_picker.get() == next {
            {
                let next_value = None;
                self.reaction_picker.revise(|value| *value = next_value);
            };
        } else {
            {
                let next_value = next;
                self.reaction_picker.revise(|value| *value = next_value);
            };
        }
    }

    pub fn confirm_redaction(self, message_id: String) {
        {
            let next_value = Some(message_id);
            self.redact_confirm.revise(|value| *value = next_value);
        };
    }

    pub fn toggle_message_menu(self, message_id: String) {
        let next = (self.message_context_menu.get().as_deref() != Some(message_id.as_str()))
            .then_some(message_id);
        {
            let next_value = next;
            self.message_context_menu
                .revise(|value| *value = next_value);
        };
    }

    pub fn close_message_menu(self) {
        {
            let next_value = None;
            self.message_context_menu
                .revise(|value| *value = next_value);
        };
    }

    pub fn begin_moderation_report(
        self,
        realm_id: String,
        effective_scope: arkret_sdk::ScopeRef,
        target_ref: String,
    ) {
        {
            let next_value = Some(ModerationReportDraft {
                realm_id,
                effective_scope,
                target_ref,
                reason: "spam".to_owned(),
                description: String::new(),
            });
            self.moderation_report_draft
                .revise(|value| *value = next_value);
        };
        {
            let next_value = None;
            self.message_context_menu
                .revise(|value| *value = next_value);
        };
    }

    pub fn update_moderation_report_reason(self, reason: String) {
        self.moderation_report_draft.revise(|values| {
            if let Some(draft) = values.as_mut() {
                draft.reason = reason;
            }
        });
    }

    pub fn update_moderation_report_description(self, description: String) {
        self.moderation_report_draft.revise(|values| {
            if let Some(draft) = values.as_mut() {
                draft.description = description;
            }
        });
    }

    pub fn cancel_moderation_report(self) {
        if !self.moderation_report_pending.get() {
            {
                let next_value = None;
                self.moderation_report_draft
                    .revise(|value| *value = next_value);
            };
        }
    }

    pub fn submit_moderation_report(self, context: ChatCommandContext) {
        let Some(draft) = self.moderation_report_draft.get() else {
            return;
        };
        if self.moderation_report_pending.get() {
            return;
        }
        if draft.reason == "other" && draft.description.trim().is_empty() {
            {
                let next_value = crate::i18n::tr("moderation.report.other_required");
                self.status_msg.revise(|value| *value = next_value);
            };
            return;
        }
        {
            let next_value = true;
            self.moderation_report_pending
                .revise(|value| *value = next_value);
        };
        let base_url = context.base_url;
        let session_credential = context.token.get();
        let principal_id = context.principal_id;
        super::task::dispatch(async move {
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
            {
                let next_value = false;
                self.moderation_report_pending
                    .revise(|value| *value = next_value);
            };
            match result {
                Ok(_) => {
                    {
                        let next_value = None;
                        self.moderation_report_draft
                            .revise(|value| *value = next_value);
                    };
                    {
                        let next_value = crate::i18n::tr("moderation.report.submitted");
                        self.status_msg.revise(|value| *value = next_value);
                    };
                }
                Err(error) => {
                    let next_value = format!(
                        "{}: {}",
                        crate::i18n::tr("moderation.report.failed"),
                        error.display()
                    );
                    self.status_msg.revise(|value| *value = next_value);
                }
            }
        });
    }

    pub fn show_blocked_message(self, message_id: String) {
        self.blocked_show_anyway
            .revise(|value| value.insert(message_id));
    }

    pub fn close_poll(self, message_id: String) {
        self.poll_cards.revise(|values| {
            if let Some(card) = values.iter_mut().find(|card| card.message_id == message_id) {
                card.closed = true;
            }
        });
        {
            let next_value = "Poll closed in this view".to_owned();
            self.status_msg.revise(|value| *value = next_value);
        };
    }

    pub fn update_edit_draft(self, content: String) {
        {
            let next_value = content;
            self.edit_draft.revise(|value| *value = next_value);
        };
    }

    pub fn cancel_edit(self) {
        {
            let next_value = None;
            self.editing_message.revise(|value| *value = next_value);
        };
    }

    pub fn cancel_redaction(self) {
        {
            let next_value = None;
            self.redact_confirm.revise(|value| *value = next_value);
        };
    }

    pub fn open_create_dialog(self) {
        {
            let next_value = true;
            self.create_dialog_open.revise(|value| *value = next_value);
        };
    }

    pub fn save_message_private(self, context: ChatCommandContext, target_ref: String) {
        if self.private_saved_targets.get().contains(&target_ref) {
            {
                let next_value = None;
                self.message_context_menu
                    .revise(|value| *value = next_value);
            };
            return;
        }
        let namespace_key = match load_chat_productivity_namespace_key(&context.authority) {
            Ok(key) => key,
            Err(error) => {
                {
                    let next_value = format!("Private save failed: {error:#}");
                    self.status_msg.revise(|value| *value = next_value);
                };
                {
                    let next_value = None;
                    self.message_context_menu
                        .revise(|value| *value = next_value);
                };
                return;
            }
        };
        let hlc = match crate::signing_stamp::issue_account_data_hlc(
            context.principal_id.as_str(),
            context.device_id.as_str(),
        ) {
            Ok(hlc) => hlc,
            Err(error) => {
                {
                    let next_value = format!("Private save failed: {error:#}");
                    self.status_msg.revise(|value| *value = next_value);
                };
                {
                    let next_value = None;
                    self.message_context_menu
                        .revise(|value| *value = next_value);
                };
                return;
            }
        };
        let item = match chat_saved_account_data_item(&namespace_key, &target_ref, hlc.as_str()) {
            Ok(item) => item,
            Err(error) => {
                {
                    let next_value = format!("Private save failed: {error:#}");
                    self.status_msg.revise(|value| *value = next_value);
                };
                {
                    let next_value = None;
                    self.message_context_menu
                        .revise(|value| *value = next_value);
                };
                return;
            }
        };
        let account_data_value =
            match crate::account_data::saved_item_account_data_value(&item.value) {
                Ok(value) => value,
                Err(error) => {
                    {
                        let next_value = format!("Private save failed: {error:#}");
                        self.status_msg.revise(|value| *value = next_value);
                    };
                    {
                        let next_value = None;
                        self.message_context_menu
                            .revise(|value| *value = next_value);
                    };
                    return;
                }
            };
        let Some(state_store) = self.command_store() else {
            return;
        };
        if let Err(error) = state_store.write(|store| store.stage_saved_account_data_item(&item)) {
            {
                let next_value = format!("Private save failed: {error:#}");
                self.status_msg.revise(|value| *value = next_value);
            };
            {
                let next_value = None;
                self.message_context_menu
                    .revise(|value| *value = next_value);
            };
            return;
        }
        self.private_saved_targets
            .revise(|value| value.insert(target_ref.clone()));
        self.private_saved_account_data.revise(|value| {
            value.insert(item.account_data_key.clone(), account_data_value.clone())
        });
        {
            let next_value = None;
            self.message_context_menu
                .revise(|value| *value = next_value);
        };
        {
            let next_value = crate::i18n::tr("message.private_saved");
            self.status_msg.revise(|value| *value = next_value);
        };

        let base_url = context.base_url;
        let api_token = context.token.get();
        let wait_for = None;
        let key = item.account_data_key;
        let status_msg = self.status_msg;
        super::task::dispatch(async move {
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
                {
                    let next_value = format!(
                        "Private save stayed local: {}",
                        crate::api_error::display_user_facing(&error)
                    );
                    status_msg.revise(|value| *value = next_value);
                };
            }
        });
    }

    pub fn toggle_shared_pin(
        self,
        context: ChatCommandContext,
        realm_id: String,
        strand_id: String,
        target_ref: String,
    ) {
        let pin_scope = shared_pin_scope_for_message(&realm_id, &strand_id);
        let existing = self
            .shared_pins
            .get()
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
                {
                    let next_value = format!("Shared pin failed: {error:#}");
                    self.status_msg.revise(|value| *value = next_value);
                };
                {
                    let next_value = None;
                    self.message_context_menu
                        .revise(|value| *value = next_value);
                };
                return;
            }
        };
        let body = match shared_pin_operation_body(&operation) {
            Ok(body) => body,
            Err(error) => {
                {
                    let next_value = format!("Shared pin failed: {error:#}");
                    self.status_msg.revise(|value| *value = next_value);
                };
                {
                    let next_value = None;
                    self.message_context_menu
                        .revise(|value| *value = next_value);
                };
                return;
            }
        };
        if removing {
            self.shared_pins.revise(|value| {
                value.retain(|pin| !(pin.matches_scope(&pin_scope) && pin.target_ref == target_ref))
            });
        } else {
            self.shared_pins.revise(|value| {
                value.push(SharedMessagePin::new(&pin_scope, target_ref.clone(), rank))
            });
        }
        {
            let next_value = None;
            self.message_context_menu
                .revise(|value| *value = next_value);
        };
        {
            let next_value = if removing {
                crate::i18n::tr("message.shared_unpin_pending")
            } else {
                crate::i18n::tr("message.shared_pin_pending")
            };
            self.status_msg.revise(|value| *value = next_value);
        };

        let Some(state_store) = self.command_store() else {
            return;
        };
        let base_url = context.base_url;
        let api_token = context.token.get();
        let wait_for = None;
        let frontier_state = context.frontier_state;
        let shared_pins = self.shared_pins;
        let status_msg = self.status_msg;
        let rollback = existing;
        super::task::dispatch(async move {
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
                            {
                                let next_value = format!("Shared pin failed: {error}");
                                status_msg.revise(|value| *value = next_value);
                            };
                            return;
                        }
                    };
                    state_store.write(|value| {
                        value.append_raw_operation(
                            operation.local_operation_id().to_string(),
                            Some(realm_id),
                            record,
                        )
                    });
                    {
                        let next_value = submitted.event_id;
                        frontier_state.revise(|value| *value = next_value);
                    };
                    {
                        let next_value = if removing {
                            crate::i18n::tr("message.shared_unpinned")
                        } else {
                            crate::i18n::tr("message.shared_pinned")
                        };
                        status_msg.revise(|value| *value = next_value);
                    };
                }
                Err(error) => {
                    if let Some(pin) = rollback {
                        shared_pins.revise(|value| value.push(pin));
                    } else {
                        shared_pins.revise(|value| {
                            value.retain(|pin| {
                                !(pin.matches_scope(&pin_scope) && pin.target_ref == target_ref)
                            })
                        });
                    }
                    {
                        let next_value = format!(
                            "Shared pin failed: {}",
                            crate::api_error::display_user_facing(&error)
                        );
                        status_msg.revise(|value| *value = next_value);
                    };
                }
            }
        });
    }

    pub fn add_reaction(
        self,
        context: ChatCommandContext,
        message_id: String,
        target_ref: String,
        emoji: String,
    ) {
        self.messages.revise(|values| {
            if let Some(message) = values.iter_mut().find(|message| message.id == message_id) {
                if let Some((_, senders)) =
                    message.reactions.iter_mut().find(|(key, _)| key == &emoji)
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
        });
        let Some(state_store) = self.command_store() else {
            return;
        };
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
                {
                    let next_value =
                        "Reaction skipped: MLS state not ready for this encrypted channel"
                            .to_owned();
                    self.status_msg.revise(|value| *value = next_value);
                };
                {
                    let next_value = None;
                    self.reaction_picker.revise(|value| *value = next_value);
                };
                return;
            }
            Err(error) => {
                {
                    let next_value = format!("Reaction skipped: {error:#}");
                    self.status_msg.revise(|value| *value = next_value);
                };
                {
                    let next_value = None;
                    self.reaction_picker.revise(|value| *value = next_value);
                };
                return;
            }
        };
        {
            let next_value = None;
            self.reaction_picker.revise(|value| *value = next_value);
        };
        let base_url = context.base_url;
        let api_token = context.token.get();
        let wait_for = None;
        let status_msg = self.status_msg;
        super::task::dispatch(async move {
            let result =
                with_authed_api_with_sync(&base_url, api_token, wait_for, |api| async move {
                    api.event_submitter()?.submit_sdk_event(&operation).await
                })
                .await;
            if let Err(error) = result {
                {
                    let next_value = format!("Reaction failed: {}", error.display());
                    status_msg.revise(|value| *value = next_value);
                };
            }
        });
    }

    pub fn revise_message(
        self,
        context: ChatCommandContext,
        message_id: String,
        target_ref: String,
        content: String,
    ) {
        let content = content.trim().to_owned();
        if content.is_empty() {
            {
                let next_value = "Edit skipped: body is empty".to_owned();
                self.status_msg.revise(|value| *value = next_value);
            };
            {
                let next_value = None;
                self.editing_message.revise(|value| *value = next_value);
            };
            return;
        }
        if self
            .messages
            .get_untracked()
            .iter()
            .any(|message| message.id == message_id && message.pending)
        {
            {
                let next_value =
                    "Wait for the current message write to settle before editing again".to_owned();
                self.status_msg.revise(|value| *value = next_value);
            };
            {
                let next_value = None;
                self.editing_message.revise(|value| *value = next_value);
            };
            return;
        }
        self.messages.revise(|values| {
            if let Some(message) = values.iter_mut().find(|message| message.id == message_id) {
                message.revisions.push(message.body.clone());
                message.body = content.clone();
                message.content_format = Some(arkret_sdk::TextFormat::Markdown);
                message.edited = true;
                message.pending = true;
                message.failed = false;
                message.error = None;
            }
        });
        {
            let next_value = None;
            self.editing_message.revise(|value| *value = next_value);
        };
        let base_url = context.base_url;
        let realm_id = context.selected_realm_id;
        let actor = context.principal_id;
        let api_token = context.token.get();
        let wait_for = None;
        let mut messages = self.messages;
        let status_msg = self.status_msg;
        // Closing the edit composer unmounts its Save Button. Keep the
        // accepted-result handler with the controller that owns the message.
        super::task::dispatch(async move {
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
                        {
                            let next_value = format!(
                                "Message update failed: {}",
                                crate::api_error::display_user_facing(&error)
                            );
                            status_msg.revise(|value| *value = next_value);
                        };
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
                    {
                        let next_value = format!(
                            "Message update failed: {}",
                            crate::api_error::display_user_facing(&error)
                        );
                        status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
            };
            match result {
                Ok(response) => {
                    messages.revise(|values| {
                        if let Ok(event_id) = arkret_sdk::EventId::new(response.event_id.clone())
                            && let Some(message) =
                                values.iter_mut().find(|message| message.id == message_id)
                        {
                            message.revision_source = Some(event_id.event_digest());
                        }
                    });
                    mark_message_command_succeeded(&mut messages, &message_id);
                    {
                        let next_value = "Message updated".to_owned();
                        status_msg.revise(|value| *value = next_value);
                    };
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
                    {
                        let next_value = format!(
                            "Message update failed: {}",
                            crate::api_error::display_user_facing(&error)
                        );
                        status_msg.revise(|value| *value = next_value);
                    };
                }
            }
        });
    }

    pub fn redact_message(self, context: ChatCommandContext, message: ChatMessage) {
        let message_id = message.id.clone();
        let target_ref = message.mutation_target_ref().to_owned();
        self.messages.revise(|values| {
            if let Some(found) = values
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
        });
        {
            let next_value = None;
            self.redact_confirm.revise(|value| *value = next_value);
        };
        let base_url = context.base_url;
        let realm_id = context.selected_realm_id;
        let actor = context.principal_id;
        let api_token = context.token.get();
        let wait_for = None;
        let frontier_state = context.frontier_state;
        let Some(state_store) = self.command_store() else {
            return;
        };
        let mut messages = self.messages;
        let status_msg = self.status_msg;
        super::task::dispatch(async move {
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
                    {
                        let next_value = format!("Message removal failed: {error:#}");
                        status_msg.revise(|value| *value = next_value);
                    };
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
                        state_store.write(|value| {
                            value.upsert_raw_operation(
                                submitted.event_id.clone(),
                                Some(realm_id),
                                payload,
                            )
                        });
                    }
                    {
                        let next_value = submitted.event_id;
                        frontier_state.revise(|value| *value = next_value);
                    };
                    mark_message_command_succeeded(&mut messages, &message_id);
                    {
                        let next_value = "Message removed".to_owned();
                        status_msg.revise(|value| *value = next_value);
                    };
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
                    {
                        let next_value = format!(
                            "Message removal failed: {}",
                            crate::api_error::display_user_facing(&error)
                        );
                        status_msg.revise(|value| *value = next_value);
                    };
                }
            }
        });
    }

    pub fn retry_message(self, context: ChatCommandContext, message: ChatMessage) {
        let Some(original_scope) = message.local_scope.clone() else {
            {
                let next_value = "Original send scope is unavailable. Reopen the original private conversation to compose a request.".to_owned();
                self.status_msg.revise(|value| *value = next_value);
            };
            return;
        };
        if matches!(original_scope, arkret_sdk::ScopeRef::Sidecar { .. }) {
            {
                let next_value = "Retry this request from its private Sidecar composer.".to_owned();
                self.status_msg.revise(|value| *value = next_value);
            };
            return;
        }
        let shared_agent_targets = if context.private_agent_scope {
            Vec::new()
        } else {
            message
                .mentions
                .iter()
                .filter_map(MentionNode::as_mention)
                .filter(|m| context.known_agent_accounts.contains(&m.subject_account_id))
                .map(|m| m.subject_account_id.clone())
                .collect::<Vec<_>>()
        };
        let local_id = message.id;
        let retry_message_id = message_id_or_new_local_id(&local_id);
        self.messages.revise(|values| {
            if let Some(found) = values
                .iter_mut()
                .find(|candidate| candidate.matches_id_or_protocol(&local_id))
            {
                found.id = retry_message_id.clone();
                found.protocol_message_id = Some(retry_message_id.clone());
                found.pending = true;
                found.failed = false;
                found.error = None;
            }
        });
        {
            let next_value = "Retrying message".to_owned();
            self.status_msg.revise(|value| *value = next_value);
        };
        let Ok(application) = crate::presentation::require_current_context() else {
            let _ = self
                .status_msg
                .try_revise(|status| *status = "The chat window is unavailable.".into());
            return;
        };
        let state_store = application.state_store.clone();
        let mention_values = mention_nodes_to_values(&message.mentions);
        let base_url = context.base_url;
        let authority = context.authority;
        let actor = context.principal_id;
        let device_id = context.device_id;
        let encrypted = context.selected_channel_security_encrypted;
        let api_token = context.token.get();
        let wait_for = None;
        let frontier_state = context.frontier_state;
        let state_store = state_store;
        let mut messages = self.messages;
        let mut status_msg = self.status_msg;
        let message_id_for_lookup = retry_message_id.clone();
        super::task::dispatch(async move {
            if let Err(error) = crate::transport::agent_interaction::require_public_targets(
                &base_url,
                api_token.clone(),
                &message.realm_id,
                shared_agent_targets,
            )
            .await
            {
                mark_message_command_failed(
                    &mut messages,
                    &message_id_for_lookup,
                    format!("Retry blocked: {error:#}"),
                );
                {
                    let next_value = format!("Retry blocked: {error:#}");
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }

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
                    {
                        let next_value = format!("send failed: {error:#}");
                        status_msg.revise(|value| *value = next_value);
                    };
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
                        {
                            let next_value = format!("send failed: {error:#}");
                            status_msg.revise(|value| *value = next_value);
                        };
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
                        {
                            let next_value = format!("send failed: {error}");
                            status_msg.revise(|value| *value = next_value);
                        };
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
                        {
                            let next_value = format!("Message send failed: {error}");
                            status_msg.revise(|value| *value = next_value);
                        };
                        return;
                    }
                };
                let build = match crate::views::secure_send::build_secure_send(
                    &api,
                    &state_store.handle(),
                    &message.realm_id,
                    &authority,
                    actor.as_str(),
                    &device_id,
                    &message.strand_id,
                    &retry_message_id,
                    message.reply_to.as_deref(),
                    &content_bytes,
                    None,
                    match &original_scope {
                        arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str()),
                        _ => None,
                    },
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
                        {
                            let next_value = format!("Message send failed: {error}");
                            status_msg.revise(|value| *value = next_value);
                        };
                        return;
                    }
                };
                let local_operation_id = build.message_local_operation_id.to_string();
                let outcome = crate::views::secure_send::submit_secure_send(
                    application.clone(),
                    &api,
                    &state_store.handle(),
                    build,
                    &message.realm_id,
                    None,
                )
                .await;
                match outcome {
                    crate::views::secure_send::SecureSendOutcome::Sent { event_id, status } => {
                        state_store.write(|value| {
                            value.mark_message_retry_replacement(
                                &message.realm_id,
                                &local_id,
                                &event_id,
                            )
                        });
                        let protocol_message_id = arkret_sdk::EventId::new(event_id.clone())
                            .ok()
                            .map(|event_id| {
                                arkret_sdk::MessageId::from_event_id(&event_id).to_string()
                            })
                            .unwrap_or_else(|| retry_message_id.clone());
                        state_store.write(|value| {
                            value.append_raw_operation(
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
                            )
                        });
                        state_store.write(|value| {
                            value.save_private_plaintext(
                                &message.realm_id,
                                &message.strand_id,
                                &format!("message:{protocol_message_id}"),
                                &message.body,
                            )
                        });
                        messages.revise(|values| {
                            if let Some(found) = values.iter_mut().find(|candidate| {
                                candidate.matches_id_or_protocol(&message_id_for_lookup)
                            }) {
                                found.id = event_id.clone();
                                found.protocol_message_id = Some(protocol_message_id);
                                found.pending = status != "committed";
                                found.failed = false;
                                found.error = None;
                            }
                        });
                        if status == "committed" {
                            {
                                let next_value = event_id;
                                frontier_state.revise(|value| *value = next_value);
                            };
                        }
                        {
                            let next_value = if status == "committed" {
                                "Message sent".to_owned()
                            } else {
                                "Message queued; waiting for server confirmation".to_owned()
                            };
                            status_msg.revise(|value| *value = next_value);
                        };
                    }
                    crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
                        mark_message_command_failed(
                            &mut messages,
                            &message_id_for_lookup,
                            message.clone(),
                        );
                        {
                            let next_value = format!("Message send failed: {message}");
                            status_msg.revise(|value| *value = next_value);
                        };
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
                        {
                            let next_value = format!("send failed: {error:#}");
                            status_msg.revise(|value| *value = next_value);
                        };
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
                    {
                        let next_value = format!("send failed: {error:#}");
                        status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
            };
            let scope = original_scope;
            match send_ordinary_chat_message(
                &api,
                state_store.handle(),
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
                    state_store.write(|value| {
                        value.mark_message_retry_replacement(
                            &message.realm_id,
                            &local_id,
                            &submitted.event_id,
                        )
                    });
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
                        Ok(raw_operation) => state_store.write(|value| {
                            value.append_raw_operation(
                                local_operation_id.clone(),
                                Some(message.realm_id.clone()),
                                raw_operation,
                            )
                        }),
                        Err(error) => tracing::error!(
                            %error,
                            event_id = %submitted.event_id,
                            "accepted retried chat operation could not be cached"
                        ),
                    }
                    messages.revise(|values| {
                        if let Some(found) = values.iter_mut().find(|candidate| {
                            candidate.matches_id_or_protocol(&message_id_for_lookup)
                        }) {
                            found.id = submitted.event_id.clone();
                            found.pending = submitted.status != garth::SendQueueStatus::Committed;
                            found.failed = false;
                            found.error = None;
                        }
                    });
                    if submitted.status == garth::SendQueueStatus::Committed {
                        {
                            let next_value = submitted.event_id;
                            frontier_state.revise(|value| *value = next_value);
                        };
                        let barrier = state_store.read(|value| value.begin_durable_flush());
                        let persisted = match barrier {
                            Ok(barrier) => barrier.wait().await,
                            Err(error) => Err(error),
                        };
                        if let Err(error) = persisted {
                            {
                                let next_value = format!(
                                    "Message committed, but this device could not save its history: {error}"
                                );
                                status_msg.revise(|value| *value = next_value);
                            };
                            return;
                        }
                    }
                    {
                        let next_value = if submitted.status == garth::SendQueueStatus::Committed {
                            "Message sent".to_owned()
                        } else {
                            "Message queued; waiting for server confirmation".to_owned()
                        };
                        status_msg.revise(|value| *value = next_value);
                    };
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
        self,
        context: ChatCommandContext,
        message_id: String,
        poll_ref: arkret_sdk::MessageId,
        option_id: String,
    ) {
        {
            let next_value = "Preparing poll vote".to_owned();
            self.status_msg.revise(|value| *value = next_value);
        };
        let actor = arkret_sdk::ActorId::account(context.authority.clone());
        let selected_circle = self
            .channels
            .get()
            .iter()
            .find(|channel| channel.strand_id == context.selected_channel_id)
            .and_then(|channel| channel.scope_circle.as_ref())
            .map(|scope| scope.circle_id.clone());
        let vote_check = self
            .poll_cards
            .get()
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
                {
                    let next_value = format!("Poll vote refused: {error}");
                    self.status_msg.revise(|value| *value = next_value);
                };
                return;
            }
        };
        self.messages.revise(|values| {
            if let Some(message) = values.iter_mut().find(|message| message.id == message_id) {
                message.pending = true;
                message.failed = false;
                message.error = None;
            }
        });
        let protection = super::poll_submission::PollSubmissionContext {
            authority: context.authority.clone(),
            device_id: context.device_id.clone(),
            circle_id: self
                .channels
                .get()
                .iter()
                .find(|channel| channel.strand_id == context.selected_channel_id)
                .and_then(|channel| channel.scope_circle.as_ref())
                .map(|scope| scope.circle_id.clone()),
        };
        let Some(state_store) = self.command_store() else {
            return;
        };
        let base_url = context.base_url;
        let realm_id = context.selected_realm_id;
        let strand_id = context.selected_channel_id;
        let actor = context.principal_id;
        let api_token = context.token.get();
        let mut messages = self.messages;
        let status_msg = self.status_msg;
        // The option Button can unmount when pending/projection state changes.
        // Keep the command with the chat controller that owns these signals.
        super::task::dispatch(async move {
            {
                let next_value = "Submitting poll vote".to_owned();
                status_msg.revise(|value| *value = next_value);
            };
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
                    {
                        let next_value = "Poll vote sent".to_owned();
                        status_msg.revise(|value| *value = next_value);
                    };
                }
                Err(error) => {
                    let error = error.display();
                    mark_message_command_failed(
                        &mut messages,
                        &message_id,
                        format!("Poll vote failed: {error}"),
                    );
                    {
                        let next_value = format!("Poll vote failed: {error}");
                        status_msg.revise(|value| *value = next_value);
                    };
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
        self,
        base_url: String,
        api_token: String,
        wait_for: Option<String>,
        realm_id: String,
        operation: crate::operation::LocalOperation,
        draft: StrandCreateDraft,
    ) {
        let Some(state_store) = self.command_store() else {
            return;
        };
        let frontier_state = draft.frontier_state;
        super::task::dispatch(async move {
            let api = match authed_api_with_sync(&base_url, api_token, wait_for) {
                Ok(api) => api,
                Err(error) => {
                    {
                        let next_value = format!("Invalid server URL: {error}");
                        self.status_msg.revise(|value| *value = next_value);
                    };
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
                    {
                        let next_value = format!("Strand create failed: {error}");
                        self.status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
            };
            let strand_id = match arkret_sdk::EventId::new(submitted.event_id.clone()) {
                Ok(event_id) => arkret_sdk::StrandId::from_event_id(&event_id).into_string(),
                Err(error) => {
                    {
                        let next_value =
                            format!("Strand created but its accepted id is invalid: {error}");
                        self.status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
            };
            self.channels.revise(|value| {
                value.push(ChannelEntity {
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
                })
            });
            self.select_channel(strand_id.clone());
            {
                let next_value = submitted.event_id.clone();
                frontier_state.revise(|value| *value = next_value);
            };
            state_store.write(|store| {
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
            });
            {
                let next_value = "Strand created".to_owned();
                self.status_msg.revise(|value| *value = next_value);
            };
            {
                let next_value = String::new();
                self.new_channel_name.revise(|value| *value = next_value);
            };
            {
                let next_value = String::new();
                self.new_channel_topic.revise(|value| *value = next_value);
            };
            {
                let next_value = false;
                self.new_channel_create_card
                    .revise(|value| *value = next_value);
            };
            {
                let next_value = crate::circle::CircleScope::Realm;
                self.new_channel_scope.revise(|value| *value = next_value);
            };
            {
                let next_value = false;
                self.create_dialog_open.revise(|value| *value = next_value);
            };
        });
    }

    fn invalidate_strand_watch_observation(&mut self, queued: bool) {
        {
            let next_value = None;
            self.strand_watch_current
                .revise(|value| *value = next_value);
        };
        {
            let next_value = queued;
            self.strand_watch_queued.revise(|value| *value = next_value);
        };
        {
            let next_value = false;
            self.watch_level_menu_open
                .revise(|value| *value = next_value);
        };
    }

    fn clear_strand_watch_observation(&mut self) {
        self.invalidate_strand_watch_observation(false);
    }

    pub fn strand_watch_write_pending(&self) -> bool {
        self.strand_watch_refresh.get().write.is_some()
    }

    pub fn strand_watch_read_running(&self) -> bool {
        self.strand_watch_refresh.get().running
    }

    pub fn strand_watch_target_is_current(
        &self,
        base_url: &str,
        credential: &str,
        request: &arkret_sdk::StrandWatchCurrentRequestBody,
    ) -> bool {
        self.strand_watch_refresh
            .get()
            .latest
            .as_ref()
            .is_some_and(|(_, target)| {
                target.base_url == base_url
                    && target.credential == credential
                    && &target.request == request
                    && target.session.check_session_identity().is_ok()
            })
    }

    /// Same-target background reads retain only a validated presentation. Each
    /// write still obtains a fresh authenticated preimage in transport::write.
    pub fn refresh_strand_watch(
        mut self,
        base_url: String,
        api_token: String,
        request: Option<arkret_sdk::StrandWatchCurrentRequestBody>,
    ) {
        let sequence = self.strand_watch_request.get_untracked().wrapping_add(1);
        let target =
            request.and_then(|request| WatchRefreshTarget::capture(base_url, api_token, request));
        let mut queue = self.strand_watch_refresh.get_untracked().clone();
        let valid_display = target.as_ref().is_some_and(|target| {
            self.strand_watch_current
                .get_untracked()
                .as_ref()
                .is_some_and(|current| current.validate_for_request(&target.request).is_ok())
        });
        let queued = self.strand_watch_queued.get_untracked()
            && self.strand_watch_current.get_untracked().is_none();
        if !queue.may_retain_presentation(target.as_ref(), valid_display, queued) {
            self.clear_strand_watch_observation();
        }
        {
            let next_value = sequence;
            self.strand_watch_request
                .revise(|value| *value = next_value);
        };
        let start = queue.enqueue(target.map(|target| (sequence, target)));
        {
            let next_value = queue.pending(
                self.strand_watch_current.get_untracked().is_some(),
                self.strand_watch_queued.get_untracked(),
            );
            self.strand_watch_pending
                .revise(|value| *value = next_value);
        };
        {
            let next_value = queue;
            self.strand_watch_refresh
                .revise(|value| *value = next_value);
        };
        if !start {
            return;
        }
        // One owner-scoped worker drains the latest read. Its publication fence
        // is invalidated before a write; it never settles the write's ticket.
        super::task::dispatch(async move {
            let mut attempted_target = None;
            let mut attempts = 0u32;
            let mut backoff = garth::RetrySchedule::new(
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(4),
            );
            loop {
                let queue = self.strand_watch_refresh.get_untracked().clone();
                if queue.write.is_some() {
                    break;
                }
                let Some((sequence, target)) = queue.latest else {
                    break;
                };
                let publication = queue.publication;
                if target.session.check_session_identity().is_err() {
                    self.clear_strand_watch_observation();
                    break;
                }
                if attempted_target.as_ref() != Some(&target) {
                    attempted_target = Some(target.clone());
                    attempts = 0;
                    backoff.reset();
                }
                attempts += 1;
                let request = target.request.clone();
                let result =
                    crate::transport::auth::with_authed_sdk_client(
                        &target.base_url,
                        target.credential.clone(),
                        |http| async move {
                            crate::transport::strand_watch::read(&http, &request).await
                        },
                    )
                    .await;
                let queue = self.strand_watch_refresh.get_untracked().clone();
                if !queue.may_publish(sequence, publication, &target) {
                    // A newer benign read does not erase a known failure for
                    // this same session/cell. A pre-write or retired-target
                    // read, however, cannot invalidate its successor's state.
                    if queue.read_owns_target(publication, &target)
                        && let Err(error) = &result
                    {
                        self.invalidate_strand_watch_observation(
                            crate::event_submit::is_durably_queued_error(error.inner()),
                        );
                    }
                    continue;
                }
                if target.session.check_session_identity().is_err() {
                    self.clear_strand_watch_observation();
                    break;
                }
                match result {
                    Ok(current) if current.validate_for_request(&target.request).is_ok() => {
                        {
                            let next_value = false;
                            self.strand_watch_queued.revise(|value| *value = next_value);
                        };
                        {
                            let next_value = super::watch_level_from_wire(
                                crate::transport::strand_watch::current_level(&current),
                            );
                            self.strand_watch_level.revise(|value| *value = next_value);
                        };
                        {
                            let next_value = Some(current);
                            self.strand_watch_current
                                .revise(|value| *value = next_value);
                        };
                        break;
                    }
                    Ok(_) => {
                        self.clear_strand_watch_observation();
                        break;
                    }
                    Err(error) => {
                        // Even a retryable read failure invalidates the old display.
                        let queued = crate::event_submit::is_durably_queued_error(error.inner());
                        self.invalidate_strand_watch_observation(queued);
                        if queued {
                            {
                                let next_value = crate::i18n::tr("chat.watch_level.queued");
                                self.status_msg.revise(|value| *value = next_value);
                            };
                        }
                        tracing::warn!(error = %error.display_diagnostic(), attempt = attempts,
                            "self watch current observation failed");
                        let Some(delay) =
                            watch_read_retry_delay(error.inner(), attempts, &mut backoff)
                        else {
                            break;
                        };
                        crate::runtime_helpers::sleep_for(delay).await;
                    }
                }
            }
            let mut queue = self.strand_watch_refresh.get_untracked().clone();
            {
                let next_value = queue.finish_read();
                self.strand_watch_pending
                    .revise(|value| *value = next_value);
            };
            {
                let next_value = queue;
                self.strand_watch_refresh
                    .revise(|value| *value = next_value);
            };
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
        if self.strand_watch_pending.get_untracked()
            || self
                .strand_watch_current
                .get_untracked()
                .as_ref()
                .is_none_or(|current| current.validate_for_request(&request).is_err())
        {
            return;
        }
        let Some(target) =
            WatchRefreshTarget::capture(base_url.clone(), api_token.clone(), request.clone())
        else {
            self.clear_strand_watch_observation();
            return;
        };
        let mut queue = self.strand_watch_refresh.get_untracked().clone();
        let Some(ticket) = queue.begin_write(&target) else {
            return;
        };
        {
            let next_value = queue;
            self.strand_watch_refresh
                .revise(|value| *value = next_value);
        };
        {
            let next_value = true;
            self.strand_watch_pending
                .revise(|value| *value = next_value);
        };
        {
            let next_value = false;
            self.watch_level_menu_open
                .revise(|value| *value = next_value);
        };
        super::task::dispatch(async move {
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
            self.finish_strand_watch_write(ticket, target, result);
        });
    }

    fn finish_strand_watch_write(
        mut self,
        ticket: u64,
        target: WatchRefreshTarget,
        result: std::result::Result<
            arkret_sdk::StrandWatchCurrentResponseBody,
            crate::transport::auth::ApiCallError,
        >,
    ) {
        let mut queue = self.strand_watch_refresh.get_untracked().clone();
        if !queue.finish_write(ticket, &target) {
            return;
        }
        {
            let next_value = queue;
            self.strand_watch_refresh
                .revise(|value| *value = next_value);
        };
        {
            let next_value = false;
            self.strand_watch_pending
                .revise(|value| *value = next_value);
        };
        if target.session.check_session_identity().is_err() {
            self.clear_strand_watch_observation();
            return;
        }
        match result {
            Ok(current) if current.validate_for_request(&target.request).is_ok() => {
                {
                    let next_value = false;
                    self.strand_watch_queued.revise(|value| *value = next_value);
                };
                {
                    let next_value = super::watch_level_from_wire(
                        crate::transport::strand_watch::current_level(&current),
                    );
                    self.strand_watch_level.revise(|value| *value = next_value);
                };
                {
                    let next_value = Some(current);
                    self.strand_watch_current
                        .revise(|value| *value = next_value);
                };
                {
                    let next_value = crate::i18n::tr("chat.watch_level.saved");
                    self.status_msg.revise(|value| *value = next_value);
                };
            }
            result => {
                let queued = result.as_ref().err().is_some_and(|error| {
                    crate::event_submit::is_durably_queued_error(error.inner())
                });
                self.invalidate_strand_watch_observation(queued);
                {
                    let next_value = crate::i18n::tr(if queued {
                        "chat.watch_level.queued"
                    } else {
                        "chat.watch_level.failed"
                    });
                    self.status_msg.revise(|value| *value = next_value);
                };
                if !queued {
                    self.refresh_strand_watch(
                        target.base_url,
                        target.credential,
                        Some(target.request),
                    );
                }
            }
        }
    }

    /// Retry only the exact durable original; a current read never settles an
    /// unknown submission and this path never authors the selected level again.
    pub fn recover_strand_watch(
        mut self,
        base_url: String,
        credential: String,
        request: arkret_sdk::StrandWatchCurrentRequestBody,
    ) {
        if self.strand_watch_pending.get_untracked() || !self.strand_watch_queued.get_untracked() {
            return;
        }
        let Some(target) =
            WatchRefreshTarget::capture(base_url.clone(), credential.clone(), request.clone())
        else {
            self.clear_strand_watch_observation();
            return;
        };
        let mut queue = self.strand_watch_refresh.get_untracked().clone();
        let Some(ticket) = queue.begin_write(&target) else {
            return;
        };
        {
            let next_value = queue;
            self.strand_watch_refresh
                .revise(|value| *value = next_value);
        };
        {
            let next_value = true;
            self.strand_watch_pending
                .revise(|value| *value = next_value);
        };
        {
            let next_value = false;
            self.watch_level_menu_open
                .revise(|value| *value = next_value);
        };
        super::task::dispatch(async move {
            let result = crate::transport::auth::with_authed_sdk_client(
                &base_url,
                credential,
                |http| async move {
                    crate::app::runtime_adapter::event_submitter(http.clone())
                        .recover_pending_strand_watch(&request)
                        .await?;
                    crate::transport::strand_watch::read(&http, &request).await
                },
            )
            .await;
            self.finish_strand_watch_write(ticket, target, result);
        });
    }

    /// Author the Circle + Strand unit that promotes a message into a private
    /// discussion.
    ///
    /// The two ids fall out of their own create Events, so the promoted
    /// indicator is only set once the whole unit lands; a half-applied promote
    /// rolls the indicator back rather than presenting itself as success.
    pub fn promote_private_discussion(
        self,
        base_url: String,
        api_token: String,
        source_id: String,
        steps: Vec<crate::event_submit::EventUnitStep>,
    ) {
        super::task::dispatch(async move {
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
                        .revise(|value| value.insert(source_id, ids.discussion_strand_id));
                }
                Err(err) => {
                    tracing::warn!("discussion promote failed: {}", err.display());
                    self.promoted_targets
                        .revise(|value| value.remove(&source_id));
                    {
                        let next_value =
                            format!("Private discussion creation failed: {}", err.display());
                        self.status_msg.revise(|value| *value = next_value);
                    };
                }
            }
        });
    }
}

fn mark_message_command_succeeded(messages: &mut Cage<Vec<ChatMessage>>, message_id: &str) {
    messages.revise(|values| {
        if let Some(message) = values
            .iter_mut()
            .find(|message| message.matches_id_or_protocol(message_id))
        {
            message.pending = false;
            message.failed = false;
            message.error = None;
        }
    });
}

/// Show the exact reason a retried message did not land.
///
/// A submission whose result is unknown leaves the row pending: the signed
/// bytes are durable, and inviting another retry would risk a duplicate of a
/// message that may already be accepted.
fn present_retry_send_failure(
    messages: &mut Cage<Vec<ChatMessage>>,
    status_msg: &mut Cage<String>,
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
    {
        let next_value = message;
        status_msg.revise(|value| *value = next_value);
    };
}

fn mark_message_command_failed(
    messages: &mut Cage<Vec<ChatMessage>>,
    message_id: &str,
    error: String,
) {
    messages.revise(|values| {
        if let Some(message) = values
            .iter_mut()
            .find(|message| message.matches_id_or_protocol(message_id))
        {
            message.pending = false;
            message.failed = true;
            message.error = Some(error);
        }
    });
}

/// What a Strand create still needs once the server has named the Strand.
pub(super) struct StrandCreateDraft {
    pub title: String,
    pub category: String,
    pub topic: Option<String>,
    pub create_card: bool,
    pub scope_circle: Option<StrandScopeCircle>,
    pub frontier_state: Cage<String>,
}

/// Each mounted target owns its signals for the lifetime of the panel. Async
/// send failures and uploads retain the original target's signals after a switch.
#[derive(Clone, Copy)]
pub(super) struct ComposerState {
    pub(super) session_generation: u64,
    pub(super) draft: Cage<String>,
    pub(super) draft_storage: Cage<&'static str>,
    pub(super) draft_saved: Cage<String>,
    pub(super) pending_drafts: Cage<std::collections::BTreeMap<String, String>>,
    pub(super) reply_to_message: Cage<Option<String>>,
    pub(super) editing_message: Cage<Option<String>>,
    pub(super) edit_draft: Cage<String>,
    pub(super) compose_dragover: Cage<bool>,
    pub(super) compose_upload_status: Cage<String>,
    pub(super) attachments: Cage<Vec<crate::attachments::DraftAttachment>>,
    pub(super) attachment_target_key: Cage<String>,
    pub(super) attachment_target_revision: Cage<u64>,
    pub(super) attachment_upload_revision: Cage<u64>,
    pub(super) message_context_menu: Cage<Option<String>>,
    pub(super) moderation_report_draft: Cage<Option<ModerationReportDraft>>,
    pub(super) moderation_report_pending: Cage<bool>,
    pub(super) status_msg: Cage<String>,
    pub(super) redact_confirm: Cage<Option<String>>,
    pub(super) reaction_picker: Cage<Option<String>>,
    pub(super) mention_picker_state: Cage<crate::messaging::mentions::MentionPickerState>,
    pub(super) attachment_menu_open: Cage<bool>,
    pub(super) poll_draft: Cage<Option<crate::messaging::polls::PollDraft>>,
    pub(super) latest_read_cursor: Cage<String>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ComposerTarget {
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    realm_id: String,
    strand_id: String,
}

fn composer_session_matches(
    context: &crate::presentation::InksonContext,
    target: &ComposerTarget,
    generation: u64,
) -> bool {
    context.session_generation.get_untracked() == generation
        && context
            .active_account
            .get_untracked()
            .as_ref()
            .is_some_and(|account| {
                account.authority == target.authority && account.device_id == target.device_id
            })
}

fn composer_state(
    context: &Rc<crate::presentation::InksonContext>,
    target: ComposerTarget,
) -> glory::ui::Result<ComposerState> {
    let scope = context.state_scope().ok_or(glory::ui::Error::Gone)?;
    context.chat_state.install(context);
    let generation = context.session_generation.get_untracked();
    if let Some(mut state) = context
        .chat_state
        .drafts
        .get_untracked()
        .get(&target)
        .copied()
    {
        if state.session_generation != generation {
            state.session_generation = generation;
            context.chat_state.drafts.revise(|drafts| {
                drafts.insert(target, state);
            });
        }
        return Ok(state);
    }
    let restored = if composer_session_matches(context, &target, generation) {
        #[cfg(target_arch = "wasm32")]
        let ready = crate::secure_key_store::wasm_secure_store_ready();
        #[cfg(not(target_arch = "wasm32"))]
        let ready = true;
        if ready {
            let secure = crate::secure_key_store::default_secure_key_store("inkson");
            context.state_store.write(|store| {
                if store.active_authority().as_ref() != Some(&target.authority) {
                    return None;
                }
                if let Err(error) =
                    store.hydrate_e2ee_plaintext_cache_with_secure_store(secure.as_ref())
                {
                    tracing::warn!(?error, "composer secure-cache hydration failed");
                    return None;
                }
                Some(store.composer_draft(&target.device_id, &target.realm_id, &target.strand_id))
            })
        } else {
            None
        }
    } else {
        None
    };
    let state = ComposerState {
        session_generation: context.session_generation.get_untracked(),
        draft: scope.cage(restored.clone().unwrap_or_default()),
        draft_storage: scope.cage(if restored.is_some() {
            "saved"
        } else {
            "memory"
        }),
        draft_saved: scope.cage(restored.unwrap_or_default()),
        pending_drafts: scope.cage(std::collections::BTreeMap::new()),
        reply_to_message: scope.cage(None),
        editing_message: scope.cage(None),
        edit_draft: scope.cage(String::new()),
        compose_dragover: scope.cage(false),
        compose_upload_status: scope.cage(String::new()),
        attachments: scope.cage(Vec::new()),
        attachment_target_key: scope.cage(String::new()),
        attachment_target_revision: scope.cage(0),
        attachment_upload_revision: scope.cage(0),
        message_context_menu: scope.cage(None),
        moderation_report_draft: scope.cage(None),
        moderation_report_pending: scope.cage(false),
        status_msg: scope.cage(String::new()),
        redact_confirm: scope.cage(None),
        reaction_picker: scope.cage(None),
        mention_picker_state: scope.cage(crate::messaging::mentions::MentionPickerState::new()),
        attachment_menu_open: scope.cage(false),
        poll_draft: scope.cage(None),
        latest_read_cursor: scope.cage(String::new()),
    };

    context.chat_state.last_seen.revise(|seen| {
        seen.insert(target.clone(), (generation, state.draft.get_untracked()));
    });
    context.chat_state.drafts.revise(|drafts| {
        drafts.insert(target, state);
    });
    Ok(state)
}

pub(super) fn install_composer_persistence(
    scope: &Scope,
    weak: std::rc::Weak<crate::presentation::InksonContext>,
) {
    scope.effect(move || {
        let Some(context) = weak.upgrade() else {
            return;
        };
        let pool = &context.chat_state;
        let generation = context.session_generation.get();
        let account = context.active_account.get();
        for (target, state) in pool.drafts.get() {
            if state.session_generation != generation
                || !account.as_ref().is_some_and(|account| {
                    account.authority == target.authority && account.device_id == target.device_id
                })
            {
                continue;
            }
            let draft = state.draft.get();
            let inflight = state.pending_drafts.get();
            let durable = if draft.is_empty() {
                inflight.values().next_back().cloned().unwrap_or_default()
            } else {
                draft
            };
            let value = (generation, durable);
            if pool.last_seen.get_untracked().get(&target) == Some(&value) {
                continue;
            }
            state.draft_storage.revise(|status| *status = "saving");
            pool.last_seen.revise(|seen| {
                seen.insert(target.clone(), value.clone());
            });
            match context
                .state_store
                .read(|store| store.capture_e2ee_cache_write_intent(&target.realm_id))
            {
                Ok(intent) => {
                    pool.pending.revise(|pending| {
                        pending.insert(target, (value.0, value.1, intent));
                    });
                }
                Err(error) => {
                    tracing::warn!(?error, "composer intent provenance unavailable");
                    state.draft_storage.revise(|status| *status = "error");
                }
            }
        }
        if pool.running.get_untracked() || pool.pending.get_untracked().is_empty() {
            return;
        }
        pool.running.revise(|running| *running = true);
        let worker = context.clone();
        super::task::chat_task(context, async move {
            loop {
                let next = worker
                    .chat_state
                    .pending
                    .revise(|pending| pending.pop_first());
                let Some((target, (generation, draft, intent))) = next else {
                    break;
                };
                if !composer_session_matches(&worker, &target, generation) {
                    continue;
                }
                let result: anyhow::Result<()> = async {
                    #[cfg(target_arch = "wasm32")]
                    anyhow::ensure!(
                        crate::secure_key_store::wasm_secure_store_ready(),
                        "encrypted storage is unavailable"
                    );
                    let secure = crate::secure_key_store::default_secure_key_store("inkson");
                    let write = worker.state_store.write(|store| -> anyhow::Result<_> {
                        store.validate_e2ee_cache_write_intent(&intent, &target.realm_id)?;
                        store.hydrate_e2ee_plaintext_cache_with_secure_store(secure.as_ref())?;
                        store.prepare_composer_draft_write_captured(
                            &target.authority,
                            &target.device_id,
                            &target.realm_id,
                            &target.strand_id,
                            draft.clone(),
                        )
                    })?;
                    crate::state::LocalStateStore::persist_captured_e2ee_cache_write_durable(
                        secure.as_ref(),
                        write,
                    )
                    .await
                }
                .await;
                if !composer_session_matches(&worker, &target, generation)
                    || worker.chat_state.last_seen.get_untracked().get(&target)
                        != Some(&(generation, draft.clone()))
                {
                    continue;
                }
                if let Some(state) = worker
                    .chat_state
                    .drafts
                    .get_untracked()
                    .get(&target)
                    .copied()
                {
                    match result {
                        Ok(()) => {
                            state.draft_saved.revise(|value| *value = draft);
                            state.draft_storage.revise(|status| *status = "saved");
                        }
                        Err(error) => {
                            tracing::warn!(?error, "composer draft durable write failed");
                            state.draft_storage.revise(|status| *status = "error");
                        }
                    }
                }
            }
            worker.chat_state.running.revise(|running| *running = false);
        });
    });
}

#[cfg(test)]
#[path = "controller_context_tests.rs"]
mod controller_context_tests;

pub(super) fn chat_controller(
    _scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    selected_realm_id: &str,
    initial_strand_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> glory::ui::Result<ChatController> {
    let root_scope = context.state_scope().ok_or(glory::ui::Error::Gone)?;
    let scope = &root_scope;
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
    let target = CommonTarget::new(authority, device_id, selected_realm_id, initial_strand_id);
    let revision = context.chat_state.revision();
    let cached = context
        .chat_state
        .controllers
        .borrow()
        .get(&target)
        .copied();
    if let Some(mut cached) = cached {
        if cached.revision != revision {
            cached
                .controller
                .selected_channel
                .revise(|value| *value = initial_selected_channel);
            cached
                .controller
                .channels
                .revise(|value| *value = initial_channels);
            cached.revision = revision;
            context
                .chat_state
                .controllers
                .borrow_mut()
                .insert(target, cached);
        }
        return Ok(cached.controller);
    }
    let selected_channel = scope.cage(initial_selected_channel);
    let selection_key = scope.cage((String::new)());
    let selection_revision = scope.cage(0_u64);
    let key = format!(
        "{authority:?}|{device_id}|{selected_realm_id}|{}",
        selected_channel.get()
    );
    if selection_key.get_untracked() != key {
        {
            let next_value = key;
            selection_key.revise(|value| *value = next_value);
        };
        let revision = selection_revision.get_untracked().wrapping_add(1);
        {
            let next_value = revision;
            selection_revision.revise(|value| *value = next_value);
        };
    }
    let composer = composer_state(
        &context,
        ComposerTarget {
            authority: authority.clone(),
            device_id: device_id.clone(),
            realm_id: selected_realm_id.to_owned(),
            strand_id: selected_channel.get(),
        },
    )?;
    let controller = ChatController {
        channels: scope.cage(initial_channels),
        selected_channel,
        messages: scope.cage((Vec::<ChatMessage>::new)()),
        draft: composer.draft,
        draft_storage: composer.draft_storage,
        draft_saved: composer.draft_saved,
        pending_drafts: composer.pending_drafts,
        typing_throttle: crate::perf::typing_throttle(scope, 3_000, 4_000),
        compose_dragover: composer.compose_dragover,
        compose_upload_status: composer.compose_upload_status,
        attachments: composer.attachments,
        attachment_target_key: composer.attachment_target_key,
        attachment_target_revision: composer.attachment_target_revision,
        attachment_upload_revision: composer.attachment_upload_revision,
        selection_revision,
        shared_pins: scope.cage((Vec::<SharedMessagePin>::new)()),
        private_saved_targets: scope.cage((std::collections::BTreeSet::<String>::new)()),
        private_saved_account_data: scope
            .cage((std::collections::BTreeMap::<String, serde_json::Value>::new)()),
        message_context_menu: composer.message_context_menu,
        moderation_report_draft: composer.moderation_report_draft,
        moderation_report_pending: composer.moderation_report_pending,
        new_channel_name: scope.cage((String::new)()),
        new_channel_topic: scope.cage((String::new)()),
        new_channel_create_card: scope.cage(false),
        create_dialog_open: scope.cage(false),
        strand_watch_level: scope.cage(WatchLevel::All),
        strand_watch_current: scope.cage(None),
        strand_watch_pending: scope.cage(false),
        strand_watch_queued: scope.cage(false),
        strand_watch_request: scope.cage(0),
        strand_watch_refresh: scope.cage((WatchRefreshQueue::default)()),
        watch_level_menu_open: scope.cage(false),
        status_msg: composer.status_msg,
        queued_outbound_local_operation_ids: scope
            .cage((std::collections::BTreeSet::<String>::new)()),
        is_online: scope.cage((navigator_online)()),
        reply_to_message: composer.reply_to_message,
        editing_message: composer.editing_message,
        edit_draft: composer.edit_draft,
        redact_confirm: composer.redact_confirm,
        reaction_picker: composer.reaction_picker,
        initial_sync_requested: scope.cage(false),
        initial_sync_finished: scope.cage(false),
        mention_picker_state: composer.mention_picker_state,
        owned_agent_slugs: scope.cage((std::collections::BTreeMap::<String, String>::new)()),
        owned_agent_sync_key_seen: scope.cage((String::new)()),
        agent_participation_visibility: scope
            .cage((std::collections::BTreeMap::<String, bool>::new)()),
        agent_participation_sync_key_seen: scope.cage((String::new)()),
        attachment_menu_open: composer.attachment_menu_open,
        poll_draft: composer.poll_draft,
        poll_cards: scope.cage((Vec::<crate::messaging::polls::PollCard>::new)()),
        typing_actors: scope.cage((Vec::<String>::new)()),
        typing_next_expires_at_ms: scope.cage(None),
        presence_states: scope.cage((std::collections::BTreeMap::<String, String>::new)()),
        presence_labels: scope.cage((std::collections::BTreeMap::<String, String>::new)()),
        presence_status_messages: scope.cage((std::collections::BTreeMap::<String, String>::new)()),
        presence_sync_key_seen: scope.cage((String::new)()),
        presence_announce_key_seen: scope.cage((String::new)()),
        presence_heartbeat_tick: scope.cage(0),
        promote_discussion_draft: scope
            .cage((crate::messaging::discussion_promote::PromoteDiscussionDraft::default)()),
        promoted_targets: scope.cage((std::collections::BTreeMap::<String, String>::new)()),
        latest_read_cursor: composer.latest_read_cursor,
        blocked_show_anyway: scope.cage((std::collections::BTreeSet::<String>::new)()),
        account_display_name: scope.cage((String::new)()),
        track_filter: scope.cage("discussion_only".to_owned()),
        left_panel_open: scope.cage(true),
        eligible_circle_scopes: scope.cage((Vec::new)()),
        eligible_circle_scope_request_key_seen: scope.cage((String::new)()),
        eligible_circle_scope_request_in_flight: scope.cage(false),
        new_channel_scope: scope.cage((crate::circle::CircleScope::default)()),
        sidecar_send_pending: scope.cage(false),
        member_handle_fetching: scope.cage((std::collections::BTreeSet::new)()),
    };
    context.chat_state.controllers.borrow_mut().insert(
        target,
        CachedChatController {
            controller,
            revision,
        },
    );
    Ok(controller)
}

#[cfg(test)]
mod composer_target_tests {
    use super::*;

    #[test]
    fn watch_refresh_coalesces_live_changes_without_retiring_the_write() {
        let mut queue = WatchRefreshQueue::<u8>::default();
        assert!(queue.enqueue(Some((1, 7))));
        let before_write = queue.publication;
        let ticket = queue.begin_write(&7).unwrap();
        for sequence in 2..20 {
            assert!(!queue.enqueue(Some((sequence, 7))));
        }
        assert!(!queue.may_publish(1, before_write, &7));
        assert!(!queue.may_publish(19, queue.publication, &7));
        // A background read's cleanup owns only `running`, never this ticket.
        assert!(
            queue.finish_read(),
            "read completion keeps the active write pending"
        );
        assert!(queue.write.is_some());
        assert!(queue.finish_write(ticket, &7));
        assert!(queue.write.is_none());
        assert!(!queue.may_publish(19, before_write, &7));
        assert!(queue.enqueue(Some((20, 7))));
        assert!(queue.may_publish(20, queue.publication, &7));
    }

    #[test]
    fn watch_replaced_target_does_not_publish_or_settle_another_write() {
        let mut queue = WatchRefreshQueue::<u8>::default();
        assert!(queue.enqueue(Some((1, 7))));
        let old_read = queue.publication;
        let old_write = queue.begin_write(&7).unwrap();
        assert!(!queue.enqueue(Some((2, 8))));
        let new_write = queue.begin_write(&8).unwrap();
        assert!(!queue.finish_write(old_write, &7));
        assert_eq!(queue.write, Some((new_write, 8)));
        assert!(!queue.may_publish(1, old_read, &7));
        assert!(queue.finish_write(new_write, &8));
        assert!(!queue.enqueue(None));
        assert!(queue.latest.is_none());
        assert!(queue.write.is_none());
        assert!(!queue.may_publish(2, queue.publication, &8));
    }

    #[test]
    fn watch_queued_retry_survives_background_reads_without_unlocking_a_write() {
        let mut queue = WatchRefreshQueue::<u8>::default();
        assert!(queue.enqueue(Some((1, 7))));
        assert!(queue.may_retain_presentation(Some(&7), false, true));
        assert!(
            !queue.pending(false, true),
            "a queued read is not a new write"
        );
        assert!(!queue.enqueue(Some((2, 7))));
        assert!(queue.may_retain_presentation(Some(&7), false, true));
        assert!(!queue.pending(false, true));
        let ticket = queue.begin_write(&7).unwrap();
        assert!(
            queue.pending(false, true),
            "only explicit recovery owns the write pending flag"
        );
        assert!(queue.finish_read());
        assert!(queue.pending(false, true));
        assert!(queue.finish_write(ticket, &7));
        assert!(!queue.pending(false, true));
        assert!(!queue.may_retain_presentation(Some(&8), false, true));
        assert!(!queue.may_retain_presentation(None, false, true));
        assert!(
            !queue.may_retain_presentation(Some(&7), false, false),
            "invalid/failed observations are not retained"
        );
    }

    #[test]
    fn watch_read_failure_remains_relevant_across_benign_refresh_but_not_write_or_target_change() {
        let mut queue = WatchRefreshQueue::<u8>::default();
        assert!(queue.enqueue(Some((1, 7))));
        let publication = queue.publication;
        assert!(!queue.enqueue(Some((2, 7))));
        assert!(!queue.may_publish(1, publication, &7));
        assert!(
            queue.read_owns_target(publication, &7),
            "a real failure still invalidates the same cell"
        );
        let ticket = queue.begin_write(&7).unwrap();
        assert!(!queue.read_owns_target(publication, &7));
        assert!(queue.finish_write(ticket, &7));
        assert!(!queue.read_owns_target(publication, &7));
        let publication = queue.publication;
        assert!(!queue.enqueue(Some((3, 8))));
        assert!(!queue.read_owns_target(publication, &7));
    }

    #[test]
    fn watch_target_is_fenced_by_complete_account_device_signer_and_credential() {
        let account = crate::test_support::authority("did:web:alice.example");
        let device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-0000000000a1").unwrap();
        let replacement_device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-0000000000a2").unwrap();
        let _scope =
            crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((&account, &device)));
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            [21; 32],
            "did:web:alice.example",
            device.as_str(),
        ));
        let _signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer.clone()));
        let request = arkret_sdk::StrandWatchCurrentRequestBody {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
            )
            .unwrap(),
            strand_id: arkret_sdk::StrandId::new(
                "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
            )
            .unwrap(),
            watcher_actor_id: arkret_sdk::ActorId::account(account.clone()),
        };
        let capture = || {
            WatchRefreshTarget::capture(
                "https://station.example".into(),
                "credential-one".into(),
                request.clone(),
            )
            .unwrap()
        };
        let target = capture();
        assert!(target == capture());
        let mut changed_credential = target.clone();
        changed_credential.credential = "credential-two".into();
        assert!(target != changed_credential);
        let mut changed_base = target.clone();
        changed_base.base_url = "https://other.example".into();
        assert!(target != changed_base);
        // Same DID at a different Station is a different complete Account.
        let other_account = crate::test_support::authority_at_station(
            "did:web:alice.example",
            "did:web:other.example",
        );
        crate::secure_key_store::set_active_device_seed_scope(Some((&other_account, &device)));
        assert!(target.session.check_session_identity().is_err());
        assert!(
            WatchRefreshTarget::capture(
                target.base_url.clone(),
                target.credential.clone(),
                request.clone()
            )
            .is_none()
        );
        crate::secure_key_store::set_active_device_seed_scope(Some((
            &account,
            &replacement_device,
        )));
        assert!(
            WatchRefreshTarget::capture(
                target.base_url.clone(),
                target.credential.clone(),
                request.clone()
            )
            .is_none(),
            "a selected Device and its active signer must be mutually bound"
        );
        crate::event_signer::replace_active_signer(Some(std::sync::Arc::new(
            crate::event_signer::build_ed25519_device_signer(
                [23; 32],
                "did:web:alice.example",
                replacement_device.as_str(),
            ),
        )));
        assert!(target != capture());
        assert!(target.session.check_session_identity().is_err());
        crate::secure_key_store::set_active_device_seed_scope(Some((&account, &device)));
        crate::event_signer::replace_active_signer(Some(std::sync::Arc::new(
            crate::event_signer::build_ed25519_device_signer(
                [22; 32],
                "did:web:alice.example",
                device.as_str(),
            ),
        )));
        assert!(target != capture());
        assert!(target.session.check_session_identity().is_err());
    }

    #[test]
    fn watch_read_retries_are_bounded_and_observe_server_delay() {
        let temporary = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 503,
            error: Box::new(
                arkret_sdk::Problem::from_code("revision_unavailable", "fixture")
                    .with_retry_after_ms(Some(5_000)),
            ),
        });
        let mut backoff = garth::RetrySchedule::new(
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(4),
        );
        assert_eq!(
            watch_read_retry_delay(&temporary, 1, &mut backoff),
            Some(std::time::Duration::from_secs(5))
        );
        assert!(watch_read_retry_delay(&temporary, 3, &mut backoff).is_none());
        let denied = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 403,
            error: Box::new(arkret_sdk::Problem::from_code("not_found", "fixture")),
        });
        assert!(watch_read_retry_delay(&denied, 1, &mut backoff).is_none());
        assert!(
            watch_read_retry_delay(&anyhow::anyhow!("invalid proof"), 1, &mut backoff).is_none()
        );
    }

    fn target(strand: &str) -> ComposerTarget {
        ComposerTarget {
            authority: crate::test_support::authority("ak:did_core:web:alice.example"),
            device_id: arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-0000000000f1")
                .unwrap(),
            realm_id: "realm".into(),
            strand_id: strand.into(),
        }
    }
    #[test]
    fn hosted_history_activation_preserves_current_draft_and_structured_binding() {
        let app = glory::ui::App::memory();
        let dir = tempfile::tempdir().unwrap();
        let context = super::controller_context_tests::context(app.scope(), dir.path());
        let original = composer_state(&context, target("a")).unwrap();
        let candidate = crate::messaging::mentions::MentionCandidate {
            subject_account_id: crate::test_support::authority("ak:did_core:web:agent.example"),
            display_name: "aa".into(),
            insert_label: "me/aa".into(),
            subtitle: String::new(),
            is_agent: true,
            is_owned_agent: true,
            controller_subject_account_id: Some(target("a").authority),
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        };
        let draft = original
            .mention_picker_state
            .revise(|picker| picker.select(candidate, "@", Some((0, 1))));
        original.draft.revise(|value| *value = draft);
        original
            .reply_to_message
            .revise(|value| *value = Some("source-reply".into()));
        for _ in 0..3 {
            let child = app.scope().child().unwrap();
            child.dispose();
            let current = composer_state(&context, target("a")).unwrap();
            current
                .draft
                .revise(|value| *value = "retained identity probe".to_owned());
            assert_eq!(original.draft.get_untracked(), "retained identity probe");
            original.draft.revise(|value| *value = "@me/aa ".to_owned());
            assert_eq!(current.draft.get_untracked(), "@me/aa ");
            assert_eq!(
                current
                    .mention_picker_state
                    .get_untracked()
                    .bound_candidates(&current.draft.get_untracked())
                    .len(),
                1
            );
            assert_eq!(
                current.reply_to_message.get_untracked().as_deref(),
                Some("source-reply")
            );
        }
    }
    #[test]
    fn composer_switch_keeps_draft_reply_edit_and_late_results_on_original_chat() {
        let app = glory::ui::App::memory();
        let dir = tempfile::tempdir().unwrap();
        let context = super::controller_context_tests::context(app.scope(), dir.path());
        let a = composer_state(&context, target("a")).unwrap();
        a.draft.revise(|value| *value = "draft a".into());
        a.reply_to_message
            .revise(|value| *value = Some("message a".into()));
        a.edit_draft.revise(|value| *value = "edited a".into());
        let b = composer_state(&context, target("b")).unwrap();
        assert!(b.draft.get_untracked().is_empty());
        b.draft.revise(|value| *value = "draft b".into());
        a.draft
            .revise(|value| *value = "restored a with attachment".into());
        a.compose_upload_status
            .revise(|value| *value = "Upload complete".into());
        assert_eq!(b.draft.get_untracked(), "draft b");
        assert!(b.compose_upload_status.get_untracked().is_empty());
        let restored = composer_state(&context, target("a")).unwrap();
        assert_eq!(restored.draft.get_untracked(), "restored a with attachment");
        assert_eq!(
            restored.reply_to_message.get_untracked().as_deref(),
            Some("message a")
        );
        assert_eq!(restored.edit_draft.get_untracked(), "edited a");
        let mut isolated = vec![target("a"); 3];
        isolated[0].authority = crate::test_support::authority("ak:did_core:web:bob.example");
        isolated[1].device_id =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-0000000000f2").unwrap();
        isolated[2].realm_id = "other realm".into();
        for target in isolated {
            assert!(
                composer_state(&context, target)
                    .unwrap()
                    .draft
                    .get_untracked()
                    .is_empty()
            );
        }
        context.chat_state.retire_session();
        assert_eq!(
            composer_state(&context, target("a"))
                .unwrap()
                .draft
                .get_untracked(),
            "restored a with attachment"
        );
    }
}
