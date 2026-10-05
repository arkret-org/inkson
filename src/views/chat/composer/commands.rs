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

/// Submit a poll and adopt the accepted Message identity for its optimistic row.
#[allow(clippy::too_many_arguments)]
pub(super) fn send_poll(
    controller: ChatController,
    base_url: String,
    api_token: String,
    operation: crate::operation::LocalOperation,
    protection: super::super::poll_submission::PollSubmissionContext,
    local_message_id: String,
    realm_id: String,
    strand_id: String,
) {
    let mut messages = controller.messages;
    let mut poll_cards = controller.poll_cards;
    let mut status_msg = controller.status_msg;
    let state_store = crate::app::SessionContext::get().state_store;
    spawn(async move {
        let result =
            crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                super::super::poll_submission::submit_poll_operation(
                    &api,
                    state_store,
                    &protection,
                    &operation,
                    &realm_id,
                    &strand_id,
                    Vec::new(), // newly created poll has no accepted response head
                )
                .await
            })
            .await;
        match result {
            Ok(event_id) => {
                let message_ref = crate::messaging::polls::poll_message_ref(
                    &arkret_sdk::EventKind::MessageCreate,
                    &event_id,
                );
                if let Some(found) = messages
                    .write()
                    .iter_mut()
                    .find(|candidate| candidate.matches_id_or_protocol(&local_message_id))
                {
                    found.protocol_message_id = message_ref.clone();
                    found.pending = false;
                    found.failed = false;
                    found.error = None;
                }
                if let Some(card) = poll_cards
                    .write()
                    .iter_mut()
                    .find(|card| card.message_id == local_message_id)
                    && let Some(message_ref) = message_ref
                {
                    card.poll_ref = arkret_sdk::MessageId::new(message_ref).ok();
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
    pub draft_at_send: String,
    pub participants: Vec<SpaceParticipant>,
}

/// Reserve (or reuse) a private sidecar for already-structured, exact Agent
/// AccountId mentions, then submit the same unchanged draft in this Send action.
pub(super) fn route_to_owned_agent_sidecar(
    controller: ChatController,
    mut sidecar_session: Signal<Option<crate::sidecar::HostedSidecarState>>,
    mut sidecar_route_pending: Signal<bool>,
    route: OwnedAgentSidecarRoute,
) {
    let mut status_msg = controller.status_msg;
    let state_store = crate::app::SessionContext::get().state_store;
    let session_fence = match crate::transport::auth::AuthoringSessionFence::capture() {
        Ok(fence) => fence,
        Err(error) => {
            sidecar_route_pending.set(false);
            status_msg.set(format!("Private Sidecar message was not sent: {error:#}"));
            return;
        }
    };
    let draft_fence = PendingSidecarDraftFence::capture_in_scope(
        controller.draft,
        controller.mention_picker_state,
        controller.selected_channel,
        sidecar_route_pending.origin_scope(),
    );
    dioxus::core::Runtime::current().in_scope(sidecar_route_pending.origin_scope(), || {
        dioxus::core::spawn(async move {
            let OwnedAgentSidecarRoute {
                base_url,
                api_token,
                trace_id,
                realm_id,
                strand_id,
                actor,
                authority,
                controller_did,
                device_id,
                mentions_enabled,
                mentions,
                body,
                draft_at_send,
                participants,
            } = route;
            let addressed_agent_ids =
                owned_agent_ids_from_composer(mentions_enabled, &mentions, &participants, &actor);
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
            let current_private_mode = if matches!(&sidecar_outcome, Ok(Some(_))) {
                require_current_private_targets(
                    &base_url,
                    api_token.clone(),
                    &realm_id,
                    &authority,
                    &mentions,
                    &addressed_agent_ids,
                )
                .await
            } else {
                Ok(())
            };
            let draft_unchanged = draft_fence.finish();
            let same_session = session_fence.check().is_ok()
                && crate::app::SessionContext::get()
                    .active_account()
                    .is_some_and(|active| {
                        active.authority == authority && active.device_id == device_id
                    });
            if !same_session {
                sidecar_route_pending.set(false);
                return;
            }
            if let Err(error) = current_private_mode {
                sidecar_route_pending.set(false);
                status_msg.set(format!("Private Sidecar message was not sent: {error:#}"));
                return;
            }
            match sidecar_outcome {
                Ok(Some(sidecar)) => {
                    let OwnedAgentSidecarEnsureResult {
                        sidecar_id,
                        view: sidecar_view,
                    } = sidecar;
                    if !draft_unchanged
                        || controller.draft.peek().as_str() != draft_at_send
                        || controller.selected_channel.peek().as_str() != strand_id
                    {
                        sidecar_route_pending.set(false);
                        status_msg.set(
                            "Private Sidecar ready. The edited draft has not been sent.".to_owned(),
                        );
                        return;
                    }
                    let native_mls_ready = crate::sidecar::native_mls_ready_for_view(
                        &state_store.read(),
                        &sidecar_view,
                    );
                    let addressed_agent_label =
                        sidecar_agent_label(&addressed_agent_ids, &participants);
                    let session = crate::sidecar::HostedSidecarState {
                        trace_id,
                        controller_account_id: sidecar_view.sidecar.controller_account_id.clone(),
                        addressed_agent_ids: addressed_agent_ids.clone(),
                        addressed_agent_label,
                        source_realm_id: realm_id.clone(),
                        source_strand_id: strand_id.clone(),
                        sidecar_id: sidecar_id.clone(),
                        access_readiness: sidecar_view.access_readiness,
                        pending_access_reconciliations: sidecar_view
                            .pending_access_reconciliations
                            .clone(),
                        mls_context: sidecar_view.mls_context.clone(),
                        native_mls_ready,
                        migrated_draft: String::new(),
                        opened_at: chrono::Utc::now(),
                    };
                    sidecar_session.set(Some(session.clone()));
                    sidecar_route_pending.set(false);
                    let source_event_id = latest_source_event_anchor(
                        &controller.messages.peek(),
                        &realm_id,
                        &strand_id,
                    );
                    send_sidecar_message_with_hosted(
                        controller,
                        sidecar_session,
                        SidecarSendRequest {
                            base_url,
                            api_token,
                            session,
                            addressed_agent_ids,
                            draft_at_send,
                            sidecar_strand_id: strand_id,
                            source_event_id,
                            actor,
                            authority,
                            device_id,
                            local_id: new_chat_local_id(),
                            body,
                            mentions,
                        },
                    );
                    return;
                }
                Ok(None) => status_msg
                    .set("Could not resolve an owned agent for the private sidecar.".to_owned()),
                Err(error) => {
                    status_msg.set(format!("Could not open private AI sidecar: {error:#}"))
                }
            }
            sidecar_route_pending.set(false);
        })
    });
}

async fn require_current_private_targets(
    base: &str,
    credential: String,
    realm: &str,
    controller: &arkret_sdk::AccountId,
    mentions: &[MentionNode],
    addressed_agent_ids: &[String],
) -> anyhow::Result<()> {
    let agents = mentions
        .iter()
        .filter_map(MentionNode::as_mention)
        .map(|mention| mention.subject_account_id.clone())
        .filter(|account| {
            addressed_agent_ids
                .iter()
                .any(|id| id == account.principal_id.as_str())
        })
        .collect::<std::collections::BTreeSet<_>>();
    anyhow::ensure!(
        !agents.is_empty()
            && addressed_agent_ids
                .iter()
                .all(|id| agents.iter().any(|agent| agent.principal_id.as_str() == id)),
        "private Agent targets require current structured AccountId mentions"
    );
    let realm = arkret_sdk::RealmId::new(realm.to_owned())?;
    let controller = controller.clone();
    crate::transport::auth::with_authed_sdk_client(base, credential, |http| async move {
        for agent in agents {
            let (mode, _, owner) =
                crate::transport::agent_interaction::read(&http, &realm, &agent).await?;
            anyhow::ensure!(
                private_target_mode_matches(mode, owner.as_ref(), &controller),
                "Agent mode or controller changed; keep the draft and review its current audience"
            );
        }
        Ok(())
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))
}

fn private_target_mode_matches(
    mode: arkret_sdk::AgentInteractionMode,
    owner: Option<&arkret_sdk::AccountId>,
    controller: &arkret_sdk::AccountId,
) -> bool {
    mode == arkret_sdk::AgentInteractionMode::Private
        && owner.is_none_or(|owner| owner == controller)
}

/// Any intervening draft/binding/Strand write cancels delayed automatic Send,
/// including editing and restoring exactly the same visible text.
struct PendingSidecarDraftFence {
    context: dioxus::dioxus_core::ReactiveContext,
    changed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl PendingSidecarDraftFence {
    #[cfg(test)]
    fn capture(
        draft: Signal<String>,
        picker: Signal<crate::messaging::mentions::MentionPickerState>,
        strand: Signal<String>,
    ) -> Self {
        Self::capture_in_scope(draft, picker, strand, draft.origin_scope())
    }

    fn capture_in_scope(
        draft: Signal<String>,
        picker: Signal<crate::messaging::mentions::MentionPickerState>,
        strand: Signal<String>,
        owner: ScopeId,
    ) -> Self {
        let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dirty = changed.clone();
        let context = dioxus::dioxus_core::ReactiveContext::new_with_callback(
            move || {
                dirty.store(true, std::sync::atomic::Ordering::SeqCst);
            },
            owner,
            std::panic::Location::caller(),
        );
        context.run_in(|| {
            let _ = draft.read();
            let _ = picker.read();
            let _ = strand.read();
        });
        Self { context, changed }
    }

    fn finish(self) -> bool {
        self.context.clear_subscribers();
        !self.changed.load(std::sync::atomic::Ordering::SeqCst)
    }
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
    pub circle_id: Option<String>,
    pub strand_id: String,
    pub actor: String,
    /// Holder-local id of the optimistic row, and the message id the Event
    /// carries until the server names it.
    pub local_id: String,
    pub body: String,
    pub reply_to: Option<String>,
    pub mentions: Vec<MentionNode>,
    pub shared_agent_targets: Vec<arkret_sdk::AccountId>,
}

/// Send a message into a plaintext Strand.
///
/// Only already-structured mentions with complete AccountIds enter the wire;
/// raw controller/slug text is inert under 0364 D2.
pub(super) fn send_plaintext_message(
    controller: ChatController,
    mut frontier_state: Signal<String>,
    request: PlaintextSendRequest,
) {
    let mut messages = controller.messages;
    let mut status_msg = controller.status_msg;
    let chat_draft = controller.draft;
    let mut state_store = crate::app::SessionContext::get().state_store;
    // A verified-current refresh can replace the composer send Button.
    // Its in-flight write belongs to the controller's message list.
    dioxus::core::Runtime::current().in_scope(messages.origin_scope(), || {
        dioxus::core::spawn(async move {
            let PlaintextSendRequest {
                base_url,
                api_token,
                wait_for,
                realm_id,
                circle_id,
                strand_id,
                actor,
                local_id,
                body,
                reply_to,
                mentions,
                shared_agent_targets,
            } = request;
            if let Some(found) = messages
                .write()
                .iter_mut()
                .find(|candidate| candidate.matches_id_or_protocol(&local_id))
            {
                found.mentions = mentions.clone();
            }
            if let Err(error) = crate::transport::agent_interaction::require_public_targets(
                &base_url,
                api_token.clone(),
                &realm_id,
                shared_agent_targets.clone(),
            )
            .await
            {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &local_id,
                    &body,
                    format!("Send blocked: {error:#}"),
                );
                return;
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
                    fail_optimistic_send_row(
                        messages,
                        &local_id,
                        format!("send failed: {error:#}"),
                    );
                    status_msg.set(format!("send failed: {error:#}"));
                    return;
                }
            };
            if let Err(error) = crate::transport::agent_interaction::require_public_targets(
                &base_url,
                api_token.clone(),
                &realm_id,
                shared_agent_targets,
            )
            .await
            {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &local_id,
                    &body,
                    format!("Send blocked: {error:#}"),
                );
                return;
            }
            let content = match chat_content_with_mentions(&body, content, &mentions) {
                Ok(content) => content,
                Err(error) => {
                    fail_optimistic_send_row(
                        messages,
                        &local_id,
                        format!("send failed: {error:#}"),
                    );
                    status_msg.set(format!("send failed: {error:#}"));
                    return;
                }
            };
            let content_for_store =
                serde_json::to_value(&content).unwrap_or(serde_json::Value::Null);
            let local_operation_id =
                crate::operation::LocalOperationId::from_holder_key(local_id.clone()).to_string();
            let api = match authed_api_with_sync(&base_url, api_token, wait_for) {
                Ok(api) => api,
                Err(error) => {
                    fail_optimistic_send_row(
                        messages,
                        &local_id,
                        format!("send failed: {error:#}"),
                    );
                    status_msg.set(format!("send failed: {error:#}"));
                    return;
                }
            };
            let scope =
                match arkret_sdk::RealmId::new(realm_id.clone()).and_then(
                    |realm_id| match circle_id {
                        Some(circle_id) => arkret_sdk::CircleId::new(circle_id).map(|circle_id| {
                            arkret_sdk::ScopeRef::Circle {
                                realm_id,
                                circle_id,
                            }
                        }),
                        None => Ok(arkret_sdk::ScopeRef::Realm { realm_id }),
                    },
                ) {
                    Ok(scope) => scope,
                    Err(error) => {
                        fail_optimistic_send_row(
                            messages,
                            &local_id,
                            format!("send failed: {error}"),
                        );
                        status_msg.set(format!("send failed: {error}"));
                        return;
                    }
                };
            // The §4.5 mention-routing sidecar exists so an encrypted Realm can
            // route a notification without revealing the mentioned DID. A
            // plaintext send already carries `mentions` in the clear, so it gets
            // no sidecar.
            let mention_values_for_store = mention_nodes_to_values(&mentions);
            match send_ordinary_chat_message(
                &api,
                crate::app::runtime_adapter::state_store_handle(state_store),
                &realm_id,
                scope,
                &strand_id,
                arkret_sdk::MessageAuthoringContent::Plaintext {
                    content,
                    metadata: None,
                },
                reply_to.as_deref(),
                local_operation_id.clone(),
            )
            .await
            {
                Ok(resp) => {
                    match serde_json::to_value(AcceptedChatMessageOperation {
                        event_id: &resp.event_id,
                        kind: event_kind_str::MESSAGE_CREATE,
                        actor_id: &actor,
                        body: &body,
                        content: &content_for_store,
                        strand_id: &strand_id,
                        message_id: &local_id,
                        mentions: &mention_values_for_store,
                        reply_to: reply_to.as_deref(),
                        status: &resp.status,
                    }) {
                        Ok(raw_operation) => state_store.write().append_raw_operation(
                            local_operation_id.clone(),
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
                        found.pending = resp.status != garth::SendQueueStatus::Committed;
                        found.failed = false;
                        found.error = None;
                    }
                    if resp.status == garth::SendQueueStatus::Committed {
                        frontier_state.set(resp.event_id.clone());
                        let barrier = state_store.read().begin_durable_flush();
                        let persisted = match barrier {
                            Ok(barrier) => barrier.wait().await,
                            Err(error) => Err(error),
                        };
                        if let Err(error) = persisted {
                            status_msg.set(format!(
                                "Message committed, but this device could not save its history: {error}"
                            ));
                            return;
                        }
                    }
                    status_msg.set(if resp.status == garth::SendQueueStatus::Committed {
                        "Message sent".to_owned()
                    } else {
                        "Message queued; waiting for server confirmation".to_owned()
                    });
                }
                Err(failure) => {
                    tracing::warn!(
                        event_id = %local_id,
                        error = %failure,
                        "chat send did not reach an accepted result"
                    );
                    present_chat_send_failure(
                        messages, status_msg, chat_draft, &local_id, &body, &failure,
                    );
                }
            }
        });
    });
}

/// Show exactly what stopped one message, and leave the row in the state that
/// matches it.
///
/// A submission whose result is unknown stays pending: the exact signed bytes
/// are durable and the drain owns them, so marking the bubble failed would
/// invite the user to author a duplicate of a message that may already exist.
pub(super) fn present_chat_send_failure(
    mut messages: Signal<Vec<ChatMessage>>,
    mut status_msg: Signal<String>,
    mut chat_draft: Signal<String>,
    local_id: &str,
    body: &str,
    failure: &garth::MessageAuthoringFailure,
) {
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    tracing::warn!(error = %failure, "ordinary message authoring failed");
    let message = crate::i18n::tr(chat_authoring_failure_message(failure));
    if matches!(
        failure,
        garth::MessageAuthoringFailure::SubmissionOutcomeUnknown { .. }
    ) {
        status_msg.set(message);
        return;
    }
    if matches!(
        failure,
        garth::MessageAuthoringFailure::Refused { code, .. } if code == "space_membership_denied"
    ) {
        messages
            .write()
            .retain(|candidate| candidate.id != local_id);
        if chat_draft().trim().is_empty() {
            chat_draft.set(body.to_owned());
        }
        status_msg.set(message);
        return;
    }
    super::super::model::fail_optimistic_chat_send(
        messages, chat_draft, status_msg, local_id, body, message,
    );
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
    pub session: crate::sidecar::HostedSidecarState,
    pub addressed_agent_ids: Vec<String>,
    pub draft_at_send: String,
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
}

pub(super) fn send_sidecar_message(controller: ChatController, request: SidecarSendRequest) {
    let hosted = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    send_sidecar_message_with_hosted(controller, hosted, request);
}

fn send_sidecar_message_with_hosted(
    controller: ChatController,
    mut hosted: Signal<Option<crate::sidecar::HostedSidecarState>>,
    request: SidecarSendRequest,
) {
    let mut messages = controller.messages;
    let mut status_msg = controller.status_msg;
    let mut chat_draft = controller.draft;
    let mut picker = controller.mention_picker_state;
    let picker_at_send = picker.peek().clone();
    let mut sending = controller.sidecar_send_pending;
    if *sending.peek() {
        return;
    }
    let authoring_fence = match crate::transport::auth::AuthoringSessionFence::capture() {
        Ok(fence)
            if crate::app::SessionContext::get()
                .active_account()
                .is_some_and(|active| {
                    active.authority == request.authority && active.device_id == request.device_id
                }) =>
        {
            fence
        }
        _ => {
            status_msg
                .set("Private Sidecar message was not sent: account session changed".to_owned());
            return;
        }
    };
    sending.set(true);
    messages.write().push(ChatMessage {
        local_scope: None,
        realm_id: request.session.source_realm_id.clone(),
        id: request.local_id.clone(),
        protocol_message_id: Some(request.local_id.clone()),
        actor_id: crate::mls_api_helpers::local_account_actor_id(&request.actor).ok(),
        sender: request.actor.clone(),
        executed_by: None,
        body: request.body.clone(),
        content_format: Some(arkret_sdk::TextFormat::Markdown),
        timestamp: chrono::Utc::now().format("%H:%M").to_string(),
        created_at: Some(chrono::Utc::now()),
        strand_id: request.session.source_strand_id.clone(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        revision_source: None,
        pending: true,
        failed: false,
        error: None,
        mentions: request.mentions.clone(),
        crypto_state: MessageCryptoState::Plaintext,
    });
    let mut reply_to = controller.reply_to_message;
    reply_to.set(None);
    let state_store = crate::app::SessionContext::get().state_store;
    dioxus::core::Runtime::current().in_scope(messages.origin_scope(), || {
        dioxus::core::spawn(async move {
            let SidecarSendRequest {
                base_url,
                api_token,
                session,
                addressed_agent_ids,
                draft_at_send,
                sidecar_strand_id,
                source_event_id,
                actor,
                authority,
                device_id,
                local_id,
                body,
                mentions,
            } = request;
            let resolved_mentions = mentions;
            let view = match crate::transport::auth::authed_api_with_sync(
                &base_url,
                api_token.clone(),
                None,
            )
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
                    let modes = require_current_private_targets(
                        &base_url,
                        api_token.clone(),
                        &session.source_realm_id,
                        &authority,
                        &resolved_mentions,
                        &addressed_agent_ids,
                    )
                    .await
                    .and_then(|_| authoring_fence.check());
                    match modes {
                        Err(error) => Err(error),
                        Ok(()) => {
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
                                &addressed_agent_ids,
                                state_store,
                                &view,
                            )
                            .await
                        }
                    }
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
                    let open_snapshot = hosted.peek().clone();
                    if let Some(mut open) = open_snapshot.filter(|open| {
                        authoring_fence.check_session_identity().is_ok()
                            && open.sidecar_id == session.sidecar_id
                            && open.controller_account_id == session.controller_account_id
                            && open
                                .matches_route(&session.source_realm_id, &session.source_strand_id)
                    }) {
                        open.addressed_agent_ids = addressed_agent_ids;
                        hosted.set(Some(open));
                    }
                    if authoring_fence.check_session_identity().is_ok()
                        && chat_draft.peek().as_str() == draft_at_send
                        && *picker.peek() == picker_at_send
                        && (controller.selected_channel)() == session.source_strand_id
                        && hosted.peek().as_ref().is_some_and(|open| {
                            open.sidecar_id == session.sidecar_id
                                && open.controller_account_id == session.controller_account_id
                                && open.matches_route(
                                    &session.source_realm_id,
                                    &session.source_strand_id,
                                )
                        })
                    {
                        chat_draft.set(String::new());
                        picker.write().clear();
                    }
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
            sending.set(false);
        })
    });
}

#[cfg(test)]
mod pending_sidecar_draft_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    type Signals = (
        Signal<String>,
        Signal<crate::messaging::mentions::MentionPickerState>,
        Signal<String>,
        Signal<bool>,
    );
    type Control = Rc<RefCell<Option<Signals>>>;

    fn harness(control: Control) -> Element {
        let draft = use_signal(|| "original private draft".to_owned());
        let picker = use_signal(crate::messaging::mentions::MentionPickerState::new);
        let strand = use_signal(|| "source strand".to_owned());
        let background_ready = use_signal(|| false);
        *control.borrow_mut() = Some((draft, picker, strand, background_ready));
        rsx! { input { value: draft() } }
    }

    #[test]
    fn delayed_private_send_rejects_a_changed_mode_or_controller() {
        let controller = crate::test_support::authority("ak:did_core:web:alice.example");
        let replacement = crate::test_support::authority("ak:did_core:web:bob.example");
        assert!(private_target_mode_matches(
            arkret_sdk::AgentInteractionMode::Private,
            None,
            &controller
        ));
        assert!(private_target_mode_matches(
            arkret_sdk::AgentInteractionMode::Private,
            Some(&controller),
            &controller
        ));
        assert!(!private_target_mode_matches(
            arkret_sdk::AgentInteractionMode::Public,
            Some(&controller),
            &controller
        ));
        assert!(!private_target_mode_matches(
            arkret_sdk::AgentInteractionMode::Private,
            Some(&replacement),
            &controller
        ));
    }

    #[test]
    fn delayed_sidecar_send_requires_unchanged_draft_binding_and_source_revision() {
        let control = Rc::new(RefCell::new(None));
        let mut dom = VirtualDom::new_with_props(harness, control.clone());
        dom.rebuild_to_vec();
        let (mut draft, mut picker, mut strand, mut background) = control.borrow().unwrap();
        dom.in_runtime(|| {
            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            background.set(true);
            assert!(
                fence.finish(),
                "background readiness must not cancel the frozen draft"
            );

            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            draft.set("ordinary edited message".into());
            draft.set("original private draft".into());
            assert!(
                !fence.finish(),
                "restoring the same text cannot restore the old Send authorization"
            );

            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            picker.write().clear();
            assert!(
                !fence.finish(),
                "mention binding writes invalidate delayed Send"
            );

            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            strand.set("different source".into());
            strand.set("source strand".into());
            assert!(
                !fence.finish(),
                "returning to the same Strand cannot resume an old Send"
            );

            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            assert!(fence.finish());
        });
    }
}

/// One encrypted chat send: build the MLS payload, submit it, and persist the
/// author's own plaintext into the actor-private sidecar.
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
    pub circle_id: Option<String>,
    pub strand_id: String,
    pub actor: String,
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    /// Holder-local id of the optimistic row.
    pub message_id: String,
    pub body: String,
    pub reply_to: Option<String>,
    pub mentions: Vec<MentionNode>,
    pub shared_agent_targets: Vec<arkret_sdk::AccountId>,
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
        circle_id,
        strand_id,
        actor,
        authority: authority_for_sidecar,
        device_id: did,
        message_id,
        body,
        reply_to,
        mentions,
        shared_agent_targets,
        backup_trigger_signal,
    } = request;
    let base_for_backup_trigger = base.clone();
    let token_for_backup_trigger = api_token.clone();
    let actor_for_backup_trigger = actor.clone();
    dioxus::core::Runtime::current().in_scope(messages.origin_scope(), || {
      dioxus::core::spawn(async move {
        if let Some(found) = messages
            .write()
            .iter_mut()
            .find(|candidate| candidate.id == message_id)
        {
            found.mentions = mentions.clone();
        }
        if let Err(error) = crate::transport::agent_interaction::require_public_targets(&base, api_token.clone(), &realm, shared_agent_targets.clone()).await {
            fail_optimistic_chat_send(messages, chat_draft, status_msg, &message_id, &body, format!("Send blocked: {error:#}"));
            return;
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
            &realm,
            &authority_for_sidecar,
            &actor,
            &did,
            &strand_id,
            &message_id,
            reply_to.as_deref(),
            &secure_content_bytes,
            None,
            circle_id.as_deref(),
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
            if let Err(error) = crate::transport::agent_interaction::require_public_targets(&base, api_token, &realm_for_record, shared_agent_targets).await {
                fail_optimistic_chat_send(messages, chat_draft, status_msg, &message_id_for_failure, &body_for_restore, format!("Send blocked: {error:#}"));
                return;
            }
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
                crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
                    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                    tracing::warn!(error = %message, "encrypted message send failed");
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
                crate::views::secure_send::SecureSendOutcome::MessageAuthoringFailed {
                    failure,
                } => {
                    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                    tracing::warn!(error = %failure, "encrypted message authoring failed");
                    present_chat_send_failure(
                        messages,
                        status_msg,
                        chat_draft,
                        &message_id_for_failure,
                        &body_for_restore,
                        &failure,
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
                found.pending = resp_status != "committed";
                found.failed = false;
                found.error = None;
            }
            if resp_status == "committed" {
                frontier_state.set(resp_event_id.clone());
            }
            status_msg.set(if resp_status == "committed" {
                "Encrypted message sent".to_owned()
            } else {
                "Encrypted message queued; waiting for server confirmation".to_owned()
            });
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
    });
}
