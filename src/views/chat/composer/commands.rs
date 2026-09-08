//! Composer writes, out of the `rsx!` and named.
//!
//! Every one of these ran as an inline `spawn(async move { … })` inside an
//! `onclick` or `ondrop` — the three message-send paths among them, the
//! longest over four hundred lines deep in the nesting.
//!
//! Several ran twice: the compact and wide composer layouts each carried their
//! own byte-identical copy of the poll send and of the owned-agent sidecar
//! route, so a fix to one could miss the other. There is one copy of each
//! here, and the layouts call it.
//!
//! The send paths take a request value rather than a positional argument list.
//! That is not cosmetic: each call site used to clone the same handful of
//! strings under a dozen different names (`actor` / `actor_for_retry` /
//! `actor_for_store`, `body_for_resolve` / `_for_store` / `_for_restore`)
//! purely because every one had to be moved into the async block separately.

use super::*;

/// Upload every dropped file to the Realm's blob store and append an
/// attachment reference to the draft for each one that lands.
///
/// Failures are collected rather than aborting the batch: a five-file drop
/// where one file is unreadable still uploads the other four, and the status
/// line reports the last error.
pub(super) fn upload_dropped_attachments(
    controller: ChatController,
    base_url: String,
    api_token: String,
    realm_id: String,
    files: Vec<dioxus::html::FileData>,
) {
    let mut chat_draft = controller.draft;
    let mut compose_upload_status = controller.compose_upload_status;
    spawn(async move {
        let api = match crate::transport::auth::authed_api_with_sync(&base_url, api_token, None) {
            Ok(api) => api,
            Err(err) => {
                compose_upload_status.set(format!(
                    "{}: {err}",
                    crate::i18n::tr("compose.upload_error"),
                ));
                return;
            }
        };
        let clients = match api.sdk_http_client() {
            Ok(http) => crate::transport::EndpointClients::from_http(http),
            Err(err) => {
                compose_upload_status.set(format!(
                    "{}: {err}",
                    crate::i18n::tr("compose.upload_error"),
                ));
                return;
            }
        };
        let mut ok_count = 0usize;
        let mut last_error: Option<String> = None;
        for file in files {
            let filename = file.name();
            let content_type = file
                .content_type()
                .unwrap_or_else(|| "application/octet-stream".to_owned());
            let bytes = match file.read_bytes().await {
                Ok(b) => b.to_vec(),
                Err(err) => {
                    last_error = Some(format!("{err}"));
                    continue;
                }
            };
            match clients
                .blob()
                .upload_bytes_scoped(bytes, &content_type, Some(&realm_id), Some(&filename))
                .await
            {
                Ok(resp) => {
                    let current = chat_draft();
                    let needs_space =
                        !current.is_empty() && !current.ends_with(' ') && !current.ends_with('\n');
                    let attachment = format!(
                        "{}[Attachment: {}]",
                        if needs_space { " " } else { "" },
                        resp.blob_ref
                    );
                    chat_draft.set(format!("{current}{attachment}"));
                    ok_count += 1;
                }
                Err(err) => {
                    last_error = Some(err.to_string());
                }
            }
        }
        if let Some(err) = last_error {
            compose_upload_status.set(format!(
                "{}: {err}",
                crate::i18n::tr("compose.upload_error"),
            ));
        } else if ok_count > 0 {
            compose_upload_status.set(format!("{ok_count} attachment(s) uploaded"));
        } else {
            compose_upload_status.set(crate::i18n::tr("compose.upload_error"));
        }
    });
}

/// Everything the typing signal is addressed with. The throttle calls back on
/// both edges, so this is built once per keystroke burst and reused.
#[derive(Clone)]
pub(super) struct TypingSignalTarget {
    pub base_url: String,
    pub realm_id: String,
    pub strand_id: String,
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    pub material: crate::signal::SignalKeyMaterial,
    pub store: crate::runtime::input::StateStoreHandle,
}

/// Announce (or withdraw) typing presence for the selected Strand.
///
/// Send failures are deliberately ignored: presence is advisory, and a status
/// line for a dropped typing indicator would be noise on every flaky keystroke.
pub(super) fn send_typing_signal(target: TypingSignalTarget, api_token: String, typing: bool) {
    spawn(async move {
        let TypingSignalTarget {
            base_url,
            realm_id,
            strand_id,
            authority,
            device_id,
            material,
            store,
        } = target;
        let _ =
            crate::transport::auth::with_event_submitter(&base_url, api_token, |sub| async move {
                sub.send_scope_signal(
                    arkret_sdk::ScopeRef::Realm {
                        realm_id: arkret_sdk::RealmId::new(realm_id)?,
                    },
                    &authority,
                    &device_id,
                    &material,
                    &crate::signal::SignalPayload::Typing {
                        strand_id: arkret_sdk::StrandId::new(strand_id)?,
                        typing,
                    },
                    &store,
                )
                .await
            })
            .await;
    });
}

/// Submit a poll create and settle the optimistic message row it left behind.
///
/// The poll's own plaintext is stored under the accepted message id, which
/// only exists once the server names the Event — so the sidecar write has to
/// happen here rather than at compose time.
#[allow(clippy::too_many_arguments)]
pub(super) fn send_poll(
    controller: ChatController,
    base_url: String,
    api_token: String,
    operation: crate::operation::LocalOperation,
    poll_kind: arkret_sdk::EventKind,
    poll_content: Option<String>,
    local_message_id: String,
    realm_id: String,
    strand_id: String,
) {
    let mut messages = controller.messages;
    let mut status_msg = controller.status_msg;
    let mut state_store = crate::app::SessionContext::get().state_store;
    spawn(async move {
        match crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&operation).await
        })
        .await
        {
            Ok(accepted) => {
                if let (Some(message_id), Some(content)) = (
                    crate::messaging::polls::poll_message_ref(&poll_kind, &accepted.event_id),
                    poll_content,
                ) {
                    state_store.write().save_private_plaintext(
                        &realm_id,
                        &strand_id,
                        &format!("message-content:{message_id}"),
                        &content,
                    );
                }
                if let Some(found) = messages
                    .write()
                    .iter_mut()
                    .find(|candidate| candidate.matches_id_or_protocol(&local_message_id))
                {
                    found.pending = false;
                    found.failed = false;
                    found.error = None;
                }
                status_msg.set("Poll sent".to_owned());
            }
            Err(error) => {
                let error_text = error.display();
                if let Some(found) = messages
                    .write()
                    .iter_mut()
                    .find(|candidate| candidate.matches_id_or_protocol(&local_message_id))
                {
                    found.pending = false;
                    found.failed = true;
                    found.error = Some(format!("Poll send failed: {error_text}"));
                }
                status_msg.set(format!("Poll send failed: {error_text}"));
            }
        }
    });
}

/// Everything the owned-agent sidecar route needs from the composer.
///
/// The compact and wide layouts each used to build these fifteen values under
/// their own local names and then run their own copy of the routine below.
pub(super) struct OwnedAgentSidecarRoute {
    pub base_url: String,
    pub api_token: String,
    pub wait_for: Option<String>,
    /// Correlates the reserve request with its `sidecar.route.requested` log
    /// line, and travels into the opened session.
    pub trace_id: String,
    pub realm_id: String,
    pub strand_id: String,
    pub actor: String,
    pub authority: arkret_sdk::AccountId,
    pub controller_did: arkret_sdk::Did,
    pub device_id: arkret_sdk::DeviceId,
    pub mentions_enabled: bool,
    pub mentions: Vec<MentionNode>,
    pub body: String,
    pub own_controller_handle: Option<String>,
    pub roster_accounts:
        std::collections::BTreeMap<arkret_sdk::DidCoreId, Option<arkret_sdk::AccountId>>,
    pub inserted_candidates: Vec<crate::messaging::mentions::MentionCandidate>,
    pub participants: Vec<SpaceParticipant>,
}

/// Reserve (or reuse) the private sidecar an `@me/<agent>` mention addresses,
/// and hand the draft over to it.
///
/// The agent selector is resolved first because the mention text alone does
/// not name an account; only the resolved mentions say which owned agent the
/// message is for.
pub(super) fn route_to_owned_agent_sidecar(
    controller: ChatController,
    mut sidecar_session: Signal<Option<crate::sidecar::HostedSidecarState>>,
    mut sidecar_route_pending: Signal<bool>,
    route: OwnedAgentSidecarRoute,
) {
    let mut status_msg = controller.status_msg;
    let state_store = crate::app::SessionContext::get().state_store;
    spawn(async move {
        let OwnedAgentSidecarRoute {
            base_url,
            api_token,
            wait_for,
            trace_id,
            realm_id,
            strand_id,
            actor,
            authority,
            controller_did,
            device_id,
            mentions_enabled,
            mut mentions,
            body,
            own_controller_handle,
            roster_accounts,
            inserted_candidates,
            participants,
        } = route;
        for mention in resolve_agent_selector_mentions(
            mentions_enabled,
            &base_url,
            api_token.clone(),
            wait_for,
            &mentions,
            &body,
            &realm_id,
            &actor,
            own_controller_handle.as_deref(),
            &roster_accounts,
        )
        .await
        {
            push_unique_mention_node(&mut mentions, mention);
        }
        let addressed_agent_ids = owned_agent_ids_from_composer(
            mentions_enabled,
            &body,
            &mentions,
            &inserted_candidates,
            &actor,
        );
        let sidecar_outcome = ensure_owned_agent_sidecar(
            &base_url,
            api_token.clone(),
            &trace_id,
            &authority,
            &controller_did,
            &device_id,
            &realm_id,
            &strand_id,
            &addressed_agent_ids,
            state_store,
        )
        .await;
        match sidecar_outcome {
            Ok(Some(sidecar)) => {
                let OwnedAgentSidecarEnsureResult {
                    sidecar_id,
                    view: sidecar_view,
                } = sidecar;
                let addressed_agent_ids = owned_agent_ids_from_mentions(&mentions, &actor);
                let native_scope = arkret_sdk::ScopeRef::Sidecar {
                    realm_id: sidecar_view.sidecar.realm_id.clone(),
                    sidecar_id: sidecar_id.clone(),
                };
                let native_mls_ready =
                    sidecar_view
                        .mls_context
                        .mls_group_id
                        .as_ref()
                        .is_some_and(|group_id| {
                            state_store
                                .read()
                                .mls_checkpoint_for_scope_and_group(
                                    &native_scope,
                                    group_id.as_str(),
                                )
                                .is_some()
                        });
                let addressed_agent_label =
                    sidecar_agent_label(&addressed_agent_ids, &participants);
                status_msg.set("Native Sidecar reserved".to_owned());
                sidecar_session.set(Some(crate::sidecar::HostedSidecarState {
                    trace_id,
                    controller_account_id: sidecar_view.sidecar.controller_account_id.clone(),
                    addressed_agent_ids,
                    addressed_agent_label,
                    source_realm_id: realm_id,
                    source_strand_id: strand_id,
                    sidecar_id,
                    access_readiness: sidecar_view.access_readiness,
                    pending_access_reconciliations: sidecar_view
                        .pending_access_reconciliations
                        .clone(),
                    mls_context: sidecar_view.mls_context,
                    native_mls_ready,
                    display_mode: arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
                    migrated_draft: body,
                    opened_at: chrono::Utc::now(),
                }));
            }
            Ok(None) => status_msg
                .set("Could not resolve an owned agent for the private sidecar.".to_owned()),
            Err(error) => status_msg.set(format!("Could not open private AI sidecar: {error:#}")),
        }
        sidecar_route_pending.set(false);
    });
}

/// One plaintext chat send, from the optimistic row to the accepted receipt.
///
/// The call site used to clone the same six values under eleven names
/// (`actor` / `actor_for_retry` / `actor_for_store`, `body_for_resolve` /
/// `_for_store` / `_for_restore`, and so on) because each had to be moved into
/// the async block separately. Naming them once here is what removes that.
pub(super) struct PlaintextSendRequest {
    pub base_url: String,
    pub api_token: String,
    pub wait_for: Option<String>,
    pub realm_id: String,
    pub strand_id: String,
    pub actor: String,
    /// Holder-local id of the optimistic row, and the message id the Event
    /// carries until the server names it.
    pub local_id: String,
    pub body: String,
    pub reply_to: Option<String>,
    pub mentions: Vec<MentionNode>,
    pub mentions_enabled: bool,
    pub own_controller_handle: Option<String>,
    pub roster_accounts:
        std::collections::BTreeMap<arkret_sdk::DidCoreId, Option<arkret_sdk::AccountId>>,
    pub plaintext_services: Vec<String>,
}

/// Send a message into a plaintext Strand.
///
/// Resolves the agent selectors first, because a `@me/<agent>` mention has no
/// account behind it until it is resolved, and the wire `mentions[]` must
/// carry complete `AccountId`s.
pub(super) fn send_plaintext_message(
    controller: ChatController,
    mut frontier_state: Signal<String>,
    request: PlaintextSendRequest,
) {
    let mut messages = controller.messages;
    let mut status_msg = controller.status_msg;
    let mut chat_draft = controller.draft;
    let mut state_store = crate::app::SessionContext::get().state_store;
    spawn(async move {
        let PlaintextSendRequest {
            base_url,
            api_token,
            wait_for,
            realm_id,
            strand_id,
            actor,
            local_id,
            body,
            reply_to,
            mut mentions,
            mentions_enabled,
            own_controller_handle,
            roster_accounts,
            plaintext_services,
        } = request;
        for mention in resolve_agent_selector_mentions(
            mentions_enabled,
            &base_url,
            api_token.clone(),
            wait_for.clone(),
            &mentions,
            &body,
            &realm_id,
            &actor,
            own_controller_handle.as_deref(),
            &roster_accounts,
        )
        .await
        {
            push_unique_mention_node(&mut mentions, mention);
        }
        if let Some(found) = messages
            .write()
            .iter_mut()
            .find(|candidate| candidate.matches_id_or_protocol(&local_id))
        {
            found.mentions = mentions.clone();
        }
        let content = match chat_content_block_for_body_with_upload(
            &base_url,
            api_token.clone(),
            wait_for.clone(),
            &realm_id,
            &body,
        )
        .await
        {
            Ok(content) => content,
            Err(error) => {
                fail_optimistic_send_row(messages, &local_id, format!("send failed: {error:#}"));
                status_msg.set(format!("send failed: {error:#}"));
                return;
            }
        };
        let op = match chat_message_create_operation_with_content(
            &realm_id,
            &actor,
            &strand_id,
            &local_id,
            &body,
            content,
            &mentions,
            reply_to.as_deref(),
        ) {
            Ok(op) => op.with_local_operation_id(
                crate::operation::LocalOperationId::from_holder_key(local_id.clone()),
            ),
            Err(error) => {
                fail_optimistic_send_row(messages, &local_id, format!("send failed: {error:#}"));
                status_msg.set(format!("send failed: {error:#}"));
                return;
            }
        };
        // The §4.5 mention-routing sidecar exists so an encrypted Realm can
        // route a notification without revealing the mentioned DID. A
        // plaintext send already carries `mentions` in the clear, so it gets
        // no sidecar.
        let mention_values_for_store = mention_nodes_to_values(&mentions);
        match submit_chat_operation_with_auth_refresh(
            &base_url,
            &actor,
            &realm_id,
            api_token,
            wait_for,
            &plaintext_services,
            &op,
        )
        .await
        {
            Ok(resp) => {
                match serde_json::to_value(AcceptedChatMessageOperation {
                    event_id: &resp.event_id,
                    kind: event_kind_str::MESSAGE_CREATE,
                    actor_id: &actor,
                    body: &body,
                    content: &op.payload()["content"],
                    strand_id: &strand_id,
                    message_id: &local_id,
                    mentions: &mention_values_for_store,
                    reply_to: reply_to.as_deref(),
                    status: &resp.status,
                }) {
                    Ok(raw_operation) => state_store.write().append_raw_operation(
                        op.local_operation_id().to_string(),
                        Some(realm_id),
                        raw_operation,
                    ),
                    Err(error) => tracing::error!(
                        %error,
                        event_id = %resp.event_id,
                        "accepted chat operation could not be cached"
                    ),
                }
                if let Some(found) = messages
                    .write()
                    .iter_mut()
                    .find(|candidate| candidate.matches_id_or_protocol(&local_id))
                {
                    found.id = resp.event_id.clone();
                    found.pending = false;
                    found.failed = false;
                    found.error = None;
                }
                frontier_state.set(resp.event_id.clone());
                status_msg.set("Message sent".to_owned());
            }
            Err(error) => {
                tracing::warn!(
                    event_id = %local_id,
                    error = %format!("{error:#}"),
                    "chat send did not reach an accepted result"
                );
                if crate::event_submit::is_durably_queued_error(&error) {
                    status_msg.set(crate::i18n::tr("chat.outbox.queued_offline"));
                    return;
                }
                let membership_denied = is_space_membership_denied_error(&error);
                let message = chat_send_error_message(&error);
                if membership_denied {
                    messages
                        .write()
                        .retain(|candidate| candidate.id != local_id);
                    if chat_draft().trim().is_empty() {
                        chat_draft.set(body.clone());
                    }
                } else {
                    fail_optimistic_send_row(messages, &local_id, message.clone());
                }
                status_msg.set(format!("Message send failed: {message}"));
            }
        }
    });
}

/// Mark the optimistic row for `local_id` failed with `error`.
///
/// Three of the plaintext path's exit arms wrote the same three fields on the
/// same lookup; a fourth arm that forgets one of them leaves a bubble
/// spinning forever.
fn fail_optimistic_send_row(mut messages: Signal<Vec<ChatMessage>>, local_id: &str, error: String) {
    if let Some(found) = messages
        .write()
        .iter_mut()
        .find(|candidate| candidate.matches_id_or_protocol(local_id))
    {
        found.pending = false;
        found.failed = true;
        found.error = Some(error);
    }
}

/// One message sent into an active private sidecar, routed back to the source
/// Strand it was composed in.
pub(super) struct SidecarSendRequest {
    pub base_url: String,
    pub api_token: String,
    pub wait_for: Option<String>,
    pub session: crate::sidecar::HostedSidecarState,
    /// Strand the routed copy is addressed to inside the sidecar.
    pub sidecar_strand_id: String,
    /// Newest source-Strand Event the routed message anchors to, when one has
    /// been seen.
    pub source_event_id: Option<String>,
    pub actor: String,
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    pub local_id: String,
    pub body: String,
    pub mentions: Vec<MentionNode>,
    pub mentions_enabled: bool,
    pub own_controller_handle: Option<String>,
    pub roster_accounts:
        std::collections::BTreeMap<arkret_sdk::DidCoreId, Option<arkret_sdk::AccountId>>,
}

pub(super) fn send_sidecar_message(controller: ChatController, request: SidecarSendRequest) {
    let mut messages = controller.messages;
    let mut status_msg = controller.status_msg;
    let chat_draft = controller.draft;
    let state_store = crate::app::SessionContext::get().state_store;
    spawn(async move {
        let SidecarSendRequest {
            base_url,
            api_token,
            wait_for,
            session,
            sidecar_strand_id,
            source_event_id,
            actor,
            authority,
            device_id,
            local_id,
            body,
            mentions,
            mentions_enabled,
            own_controller_handle,
            roster_accounts,
        } = request;
        let mut resolved_mentions = mentions;
        for mention in resolve_agent_selector_mentions(
            mentions_enabled,
            &base_url,
            api_token.clone(),
            wait_for,
            &resolved_mentions,
            &body,
            &session.source_realm_id,
            &actor,
            own_controller_handle.as_deref(),
            &roster_accounts,
        )
        .await
        {
            push_unique_mention_node(&mut resolved_mentions, mention);
        }
        let view =
            match crate::transport::auth::authed_api_with_sync(&base_url, api_token.clone(), None)
                .and_then(|api| api.sdk_http_client())
            {
                Ok(http) => http
                    .agent_sidecar_get(&session.sidecar_id)
                    .await
                    .map_err(anyhow::Error::from),
                Err(error) => Err(error),
            };
        let outcome = match view {
            Ok(view) => {
                super::submit_source_routed_sidecar_message(
                    &base_url,
                    api_token,
                    &actor,
                    &authority,
                    &device_id,
                    &session.source_realm_id,
                    &session.source_strand_id,
                    &sidecar_strand_id,
                    source_event_id.as_deref(),
                    &body,
                    &resolved_mentions,
                    &session.addressed_agent_ids,
                    state_store,
                    &view,
                )
                .await
            }
            Err(error) => Err(error),
        };
        match outcome {
            Ok(routed) => {
                if let Some(found) = messages
                    .write()
                    .iter_mut()
                    .find(|candidate| candidate.matches_id_or_protocol(&local_id))
                {
                    found.id = routed.event_id;
                    found.pending = false;
                    found.failed = false;
                    found.error = None;
                    found.mentions = resolved_mentions;
                }
                status_msg.set("Private Sidecar message sent".to_owned());
            }
            Err(error) => fail_optimistic_chat_send(
                messages,
                chat_draft,
                status_msg,
                &local_id,
                &body,
                format!("Private Sidecar message was not sent: {error:#}"),
            ),
        }
    });
}

/// One encrypted chat send: resolve selectors, build the MLS payload, submit
/// it, and persist the author's own plaintext into the actor-private sidecar.
///
/// The author cannot decrypt their own ciphertext on a later device, so the
/// sidecar copy is what makes their own messages readable after a reload. It
/// is written from the accepted receipt, which is the first point the
/// protocol message id exists.
pub(super) struct EncryptedSendRequest {
    pub base_url: String,
    pub api_token: String,
    pub wait_for: Option<String>,
    pub realm_id: String,
    pub strand_id: String,
    pub actor: String,
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    /// Holder-local id of the optimistic row.
    pub message_id: String,
    pub body: String,
    pub reply_to: Option<String>,
    pub mentions: Vec<MentionNode>,
    pub mentions_enabled: bool,
    pub own_controller_handle: Option<String>,
    pub roster_accounts:
        std::collections::BTreeMap<arkret_sdk::DidCoreId, Option<arkret_sdk::AccountId>>,
    /// Present only when the MLS backup prompt is mounted; a first encrypted
    /// write arms it.
    pub backup_trigger_signal: Option<Signal<bool>>,
}

pub(super) fn send_encrypted_message(
    controller: ChatController,
    mut frontier_state: Signal<String>,
    request: EncryptedSendRequest,
) {
    let mut messages = controller.messages;
    let mut status_msg = controller.status_msg;
    let chat_draft = controller.draft;
    let mut state_store = crate::app::SessionContext::get().state_store;
    let EncryptedSendRequest {
        base_url: base,
        api_token,
        wait_for,
        realm_id: realm,
        strand_id,
        actor,
        authority: authority_for_sidecar,
        device_id: did,
        message_id,
        body,
        reply_to,
        mentions,
        mentions_enabled,
        own_controller_handle,
        roster_accounts,
        backup_trigger_signal,
    } = request;
    let base_for_backup_trigger = base.clone();
    let token_for_backup_trigger = api_token.clone();
    let actor_for_backup_trigger = actor.clone();
    spawn(async move {
        let mut mentions = mentions;
        for mention in resolve_agent_selector_mentions(
            mentions_enabled,
            &base,
            api_token.clone(),
            wait_for.clone(),
            &mentions,
            &body,
            &realm,
            &actor,
            own_controller_handle.as_deref(),
            &roster_accounts,
        )
        .await
        {
            push_unique_mention_node(&mut mentions, mention);
        }
        if let Some(found) = messages
            .write()
            .iter_mut()
            .find(|candidate| candidate.id == message_id)
        {
            found.mentions = mentions.clone();
        }
        // Encrypt the canonical Content Block JSON with
        // its structured mention nodes. The UI-only
        // `@me` alias has already resolved to the real
        // controller handle before this content enters
        // MLS ciphertext.
        let actor_mentions = mentions
            .iter()
            .filter_map(|mention| mention.as_mention().cloned())
            .collect::<Vec<_>>();
        let audience_mentions = mentions
            .iter()
            .filter_map(|mention| mention.as_audience_mention().cloned())
            .collect::<Vec<_>>();
        let mut secure_content_block = match chat_content_block_for_body(&body) {
            Ok(content) => content,
            Err(err) => {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id,
                    &body,
                    format!("Send Secure rejected message content: {err:#}"),
                );
                return;
            }
        };
        if !actor_mentions.is_empty() {
            secure_content_block = match secure_content_block.with_mentions(actor_mentions) {
                Ok(content) => content,
                Err(err) => {
                    fail_optimistic_chat_send(
                        messages,
                        chat_draft,
                        status_msg,
                        &message_id,
                        &body,
                        format!("Send Secure could not encode mentions: {err}"),
                    );
                    return;
                }
            };
        }
        if !audience_mentions.is_empty() {
            secure_content_block =
                match secure_content_block.with_audience_mentions(audience_mentions) {
                    Ok(content) => content,
                    Err(err) => {
                        fail_optimistic_chat_send(
                            messages,
                            chat_draft,
                            status_msg,
                            &message_id,
                            &body,
                            format!("Send Secure could not encode audience mentions: {err}"),
                        );
                        return;
                    }
                };
        }
        let secure_content_value = match sdk_payload_value(
            secure_content_block.to_value(),
            "chat encrypted content block serialize",
        ) {
            Ok(value) => value,
            Err(err) => {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id,
                    &body,
                    format!("Send Secure could not encode message content: {err:#}"),
                );
                return;
            }
        };
        let secure_content_bytes = match serde_json::to_vec(&secure_content_value) {
            Ok(bytes) => bytes,
            Err(err) => {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id,
                    &body,
                    format!("Send Secure could not encode message content: {err}"),
                );
                return;
            }
        };
        let content_for_sidecar = match String::from_utf8(secure_content_bytes.clone()) {
            Ok(content) => content,
            Err(err) => {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id,
                    &body,
                    format!("Send Secure could not preserve message content: {err}"),
                );
                return;
            }
        };
        let seal_view = state_store.read().seal_view_for_realm(&realm);
        let api = match authed_api_with_sync(&base, api_token.clone(), wait_for) {
            Ok(api) => api,
            Err(error) => {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id,
                    &body,
                    format!("Send Secure failed: {error}"),
                );
                return;
            }
        };
        // Shared MLS core: encrypt → forced ak.mls.commit
        // envelope (governance / prev→post epoch /
        // Security Frontier) → spec
        // `ak.schema.encrypted_envelope.v1` wrap →
        // `ak.schema.encrypted_envelopeis mirrors the
        // shared secure send builder.
        let secure_build = match crate::views::secure_send::build_secure_send(
            &api,
            state_store,
            &seal_view,
            &realm,
            &authority_for_sidecar,
            &actor,
            &did,
            &strand_id,
            &message_id,
            reply_to.as_deref(),
            &secure_content_bytes,
            None,
            None,
            None,
        )
        .await
        {
            Ok(build) => build,
            Err(message) => {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id,
                    &body,
                    message,
                );
                return;
            }
        };
        let base = base.clone();
        let realm_for_record = realm.clone();
        let device_for_sidecar_backup = did.clone();
        // X9: capture identifiers needed by the
        // encrypted Ok(resp) arm to (A) clear the
        // optimistic bubble's `pending` flag and (B)
        // persist the message plaintext into the
        // author-owned sidecar so reload / a new
        // device can render the author's own
        // (otherwise undecryptable) messages.
        let message_id_for_lookup = message_id.clone();
        // X10.6: also persisted into the raw_operation
        // record below so the tab-switch / reload
        // rebuild can reconstruct the sidecar key.
        // Used as the fallback when the accepted event
        // id cannot derive a protocol message id.
        let message_id_for_record = message_id.clone();
        let actor_for_record = actor.clone();
        // The synced event carries this exact strand_id
        // string (the payload was built with
        // `strand_id_value(&strand_id)`, which wraps it
        // verbatim), so the read-side sidecar lookup
        // keyed on the event's `strand_id` matches.
        let strand_id_for_sidecar = strand_id.clone();
        let strand_id_for_record = strand_id.clone();
        let content_for_sidecar = content_for_sidecar.clone();
        // P2: recoverable draft — if the encrypted send
        // fails we restore the composer text instead of
        // losing it.
        let body_for_restore = body.clone();
        let message_id_for_failure = message_id.clone();
        // Capture the message op id BEFORE the build is
        // moved into the shared submitter — the encrypted
        // raw_operation record (X10.6 sidecar re-key) is
        // keyed on it.
        let msg_local_op_id = secure_build.message_local_operation_id.to_string();
        spawn(async move {
            // Shared submit: forced ak.mls.commit first
            // (persist-on-accept snapshot + §7.10 backup
            // schedule + move record), then the encrypted
            // ak.message.create.
            let outcome = crate::views::secure_send::submit_secure_send(
                &api,
                state_store,
                secure_build,
                &realm_for_record,
                None,
            )
            .await;
            let resp = match outcome {
                crate::views::secure_send::SecureSendOutcome::Sent { event_id, status } => {
                    (event_id, status)
                }
                crate::views::secure_send::SecureSendOutcome::CommitFailed { message }
                | crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
                    // P2: reconcile the optimistic bubble so
                    // it doesn't spin forever, and keep the
                    // draft recoverable.
                    fail_optimistic_chat_send(
                        messages,
                        chat_draft,
                        status_msg,
                        &message_id_for_failure,
                        &body_for_restore,
                        message,
                    );
                    return;
                }
            };
            let (resp_event_id, resp_status) = resp;
            // The read-side projection derives the
            // protocol message id from the accepted
            // event id
            // (`MessageId::from_event_id`), so the
            // author sidecar and the raw-op record
            // must key on that same derived id.
            // Keying on the pre-submit local id
            // orphaned the plaintext and left the
            // author's own message undecryptable on
            // echo / reload.
            let protocol_message_id = arkret_sdk::EventId::new(resp_event_id.clone())
                .ok()
                .map(|event_id| {
                    arkret_sdk::MessageId::from_event_id(&event_id)
                        .as_str()
                        .to_owned()
                })
                .unwrap_or_else(|| message_id_for_record.clone());
            {
                let mut store = state_store.write();
                // X10.6: persist the message identity
                // (message_id + strand_id + actor), NOT the
                // plaintext body, into the raw_operation
                // record so the tab-switch / reload rebuild
                // can reconstruct the sidecar key
                // `message:{message_id}` under `strand_id`.
                // `message_id` is the protocol id derived
                // from the accepted event id, matching the
                // read-side projection
                // (`message_protocol_message_id_from_candidates`
                // derives from `event_id` first).
                // The body lives only in the account-private
                // `mls_private_plaintext` sidecar saved just
                // below. `encrypted_content` marks the row as
                // E2EE for readers with no sidecar (another
                // device / member).
                store.append_raw_operation(
                    msg_local_op_id.clone(),
                    Some(realm_for_record.clone()),
                    json!({
                        "event_id": resp_event_id.clone(),
                        "kind": event_kind_str::MESSAGE_CREATE,
                        "actor_id": actor_for_record.clone(),
                        "strand_id": strand_id_for_record.clone(),
                        "message_id": protocol_message_id.clone(),
                        "encrypted_content": true,
                        "status": resp_status.clone(),
                    }),
                );
                // BUG B (X9): persist the message plaintext
                // into the author-owned sidecar so reload / a
                // new device can render the author's own
                // encrypted messages (OpenMLS forbids an
                // author from decrypting their own
                // ciphertext). Keyed by
                // `message:{protocol_message_id}` under the
                // discussion strand — the same derived id the
                // read side looks up — sharing the
                // `mls_private_plaintext` map that the X5.3
                // cross-device backup already snapshots.
                store.save_private_plaintext(
                    &realm_for_record,
                    &strand_id_for_sidecar,
                    &format!("message:{protocol_message_id}"),
                    &content_for_sidecar,
                );
            }
            // The optimistic row is allowed to settle
            // only after both durable stores contain
            // the accepted message identity and the
            // author-owned plaintext. A hard reload
            // immediately after the UI reports success
            // must not race either IndexedDB write.
            let durable_result: anyhow::Result<()> = async {
                let account_barrier = state_store.read().begin_durable_flush()?;
                let e2ee_write = state_store.read().e2ee_plaintext_cache_secure_write()?;
                account_barrier.wait().await?;
                if let Some((key, Some(json))) = e2ee_write {
                    crate::secure_key_store::default_secure_key_store("inkson")
                        .store_secret_durable(&key, &json)
                        .await?;
                }
                Ok(())
            }
            .await;
            if let Err(error) = durable_result {
                let message = format!(
                    "Encrypted message was accepted, but local recovery state could not be persisted: {error}"
                );
                if let Some(found) = messages
                    .write()
                    .iter_mut()
                    .find(|candidate| candidate.matches_id_or_protocol(&message_id_for_lookup))
                {
                    found.pending = false;
                    found.failed = true;
                    found.error = Some(message.clone());
                }
                status_msg.set(message);
                return;
            }
            // BUG A (X9): clear the optimistic bubble's
            // `pending` spinner now that the server accepted
            // the encrypted message (mirrors the plaintext
            // path). Reconcile the local id to the server
            // event_id so the synced copy dedups against this
            // echo.
            if let Some(found) = messages
                .write()
                .iter_mut()
                .find(|candidate| candidate.matches_id_or_protocol(&message_id_for_lookup))
            {
                found.id = resp_event_id.clone();
                found.protocol_message_id = Some(protocol_message_id.clone());
                found.pending = false;
                found.failed = false;
                found.error = None;
            }
            frontier_state.set(resp_event_id.clone());
            status_msg.set("Encrypted message sent".to_owned());
            crate::components::schedule_mls_recovery_backups_after_encrypted_write(
                base_for_backup_trigger.clone(),
                token_for_backup_trigger.clone(),
                authority_for_sidecar.clone(),
                actor_for_backup_trigger.clone(),
                device_for_sidecar_backup.to_string(),
                state_store,
            );

            // X11.2 — first-write trigger. After this
            // encrypted send landed, auto-back up the
            // account secret when possible; otherwise
            // fall back to the prompt. Best-effort.
            if let Some(signal) = backup_trigger_signal {
                crate::components::maybe_auto_backup_mls_after_encrypted_write(
                    base_for_backup_trigger.clone(),
                    token_for_backup_trigger.clone(),
                    authority_for_sidecar.clone(),
                    actor_for_backup_trigger.clone(),
                    device_for_sidecar_backup.to_string(),
                    crate::app::runtime_adapter::state_store_handle(state_store),
                    signal,
                )
                .await;
            }

            // Audit RYW receipts are issued by the Events API
            // node, witness, or bound audit service after an
            // accepted audit access/release Event. An end-user
            // client MUST NOT manufacture one after an ordinary
            // message send, including inside a Direct Conversation.
        });
    });
}
