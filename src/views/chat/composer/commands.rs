//! Target-owned composer commands and exact submission recovery.
//!
//! Every one of these ran as an inline `super::super::task::dispatch(async move { … })` inside an
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

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "commands_context_tests.rs"]
mod context_tests;

/// Keep the submitted text recoverable until the original target receives a
/// committed result or the durable exact-byte queue takes ownership. Only a
/// definite failure restores an empty composer; pending submissions must not
/// invite duplicate authoring, and new text always remains the current draft.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ComposerSubmissionState {
    Recoverable,
    DurablePending,
    Committed,
}

struct PendingComposerDraft {
    draft: Cage<String>,
    pending: Cage<std::collections::BTreeMap<String, String>>,
    operation: String,
    body: String,
    submission: ComposerSubmissionState,
    attachments: Cage<Vec<crate::attachments::DraftAttachment>>,
    attachment_ids: Vec<String>,
}

impl PendingComposerDraft {
    fn new(controller: ChatController, operation: &str, body: &str) -> Self {
        let pending = controller.pending_drafts;
        pending.revise(|value| value.insert(operation.to_owned(), body.to_owned()));
        Self {
            draft: controller.draft,
            pending,
            operation: operation.to_owned(),
            body: body.to_owned(),
            submission: ComposerSubmissionState::Recoverable,
            attachments: controller.attachments,
            attachment_ids: controller
                .attachments
                .get_untracked()
                .iter()
                .map(|a| a.id.clone())
                .collect(),
        }
    }

    fn record_send_status(&mut self, status: garth::SendQueueStatus) {
        // Borrow the whole guard so async closures retain its Drop state until
        // submission completes, rather than capturing only a state field.
        self.submission = match status {
            garth::SendQueueStatus::Committed => ComposerSubmissionState::Committed,
            garth::SendQueueStatus::Queued | garth::SendQueueStatus::Forwarding => {
                ComposerSubmissionState::DurablePending
            }
            garth::SendQueueStatus::Rejected
            | garth::SendQueueStatus::Failed
            | garth::SendQueueStatus::Cancelled => ComposerSubmissionState::Recoverable,
        };
    }

    fn record_failure(&mut self, failure: &garth::MessageAuthoringFailure) {
        if failure.recovery() == garth::MessageAuthoringRecovery::ReplayExactSubmission {
            // The original queue and optimistic row own this pending result.
            // Remove our transient draft reservation without making it editable.
            self.submission = ComposerSubmissionState::DurablePending;
        }
    }
}

impl Drop for PendingComposerDraft {
    fn drop(&mut self) {
        if self.submission != ComposerSubmissionState::Recoverable {
            let _ = self.attachments.try_revise(|attachments| {
                attachments.retain(|a| !self.attachment_ids.contains(&a.id))
            });
        }
        let _ = self
            .pending
            .try_revise(|pending| pending.remove(&self.operation));
        if self.submission == ComposerSubmissionState::Recoverable {
            let _ = self.draft.try_revise(|draft| {
                if draft.is_empty() {
                    *draft = self.body.clone();
                }
            });
        }
    }
}

/// Prepare and recover exact attachment objects in the account's private vault.
pub(super) fn upload_dropped_attachments(
    controller: ChatController,
    base_url: String,
    api_token: String,
    scope: Option<arkret_sdk::ScopeRef>,
    files: Vec<super::files::AttachmentFile>,
) {
    let status = controller.compose_upload_status;
    let Some(scope) = scope else {
        {
            let next_value = "Attachment upload requires a verified conversation scope.".into();
            status.revise(|value| *value = next_value);
        };
        return;
    };
    let selected_is_private = controller.channels.get_untracked().iter().any(|channel| {
        channel.strand_id == controller.selected_channel.get_untracked()
            && channel.is_private_sidecar
    });
    if selected_is_private && !matches!(scope, arkret_sdk::ScopeRef::Sidecar { .. }) {
        {
            let next_value = "Attachment upload requires a verified conversation scope.".into();
            status.revise(|value| *value = next_value);
        };
        return;
    }
    let attachments = controller.attachments;
    let Some(session) = application_context(controller) else {
        return;
    };
    let generation = session.session_generation.get_untracked();
    let selected = controller.selected_channel.get_untracked().clone();
    let target_revision = controller.attachment_target_revision.get_untracked();
    let upload_revision = controller.attachment_upload_revision;
    let run = upload_revision.get_untracked().wrapping_add(1);
    {
        let next_value = run;
        upload_revision.revise(|value| *value = next_value);
    };
    let selection_revision = controller.selection_revision.get_untracked();
    let draft = controller.draft.get_untracked().clone();
    let account = session.active_account.get_untracked().clone();
    let store = session.state_store.handle();
    super::super::task::dispatch(async move {
        let result = async {
            let account = account.ok_or_else(|| anyhow::anyhow!("no active attachment account"))?;
            let strand = arkret_sdk::StrandId::new(selected.clone())?;
            let active = || {
                session.session_generation.get_untracked() == generation
                    && upload_revision.get_untracked() == run
                    && controller.selected_channel.get_untracked() == selected
                && controller.attachment_target_revision.get_untracked() == target_revision
                && controller.selection_revision.get_untracked() == selection_revision
                    && controller.draft.get_untracked() == draft
                    && session.active_account.get_untracked().as_ref().is_some_and(|a| {
                        a.authority == account.authority && a.device_id == account.device_id
                    })
            };
            anyhow::ensure!(active(), "attachment session or draft changed");
            let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
            let vault = crate::outbound_store::InksonOutboundStore::open(
                &account.authority,
                crate::outbound_store::OutboundLane::Standard,
            )?;
            let clients = crate::transport::EndpointClients::from_http(
                crate::transport::auth::authed_api_ready(&base_url, api_token).await?.sdk_http_client()?,
            );
            anyhow::ensure!(active(), "attachment session or target changed");
            for file in files {
                anyhow::ensure!(
                    file.size() <= 64 * 1024 * 1024,
                    "attachment exceeds the 64 MiB client limit"
                );
                let input = crate::mls::send_gate::MlsSendGateInput::capture(&store, &scope);
                let gate = crate::mls::send_gate::resolve_restorable_mls_send_gate(
                    &input,
                    &scope,
                    &account.device_id,
                )
                .await?;
                anyhow::ensure!(active(), "attachment session or draft changed");
                let salt = arkret_crypto::blob_aead::fresh_content_key_salt()?;
                let (context, checkpoint, state_tree_ref, nonce_prefix) = match gate {
                    crate::mls::send_gate::MlsSendGate::Plaintext => {
                        anyhow::ensure!(
                            !matches!(scope, arkret_sdk::ScopeRef::Sidecar { .. }),
                            "private attachments require MLS"
                        );
                        (None, None, None, None)
                    }
                    crate::mls::send_gate::MlsSendGate::Encrypted(current) => {
                        let checkpoint = crate::mls::read_durable_checkpoint(&store,&scope).await?
                            .ok_or_else(|| {
                                anyhow::anyhow!("missing durable attachment checkpoint")
                            })?;
                        anyhow::ensure!(
                            checkpoint.group_state_event_id.as_ref()
                                == Some(&current.current_mls_commit_event_ref)
                                && checkpoint.epoch == current.epoch,
                            "attachment winning state changed"
                        );
                        (
                            Some(arkret_models_crypto::AttachmentContentKeyContext {
                                effective_scope: scope.clone(),
                                genesis_event_ref: current.genesis_event_ref,
                                epoch: current.epoch,
                                scheme: arkret_crypto::blob_aead::SCHEME_STREAM.into(),
                                encryption_algorithm: arkret_crypto::blob_aead::ALG_STREAM_XCHACHA
                                    .into(),
                                content_key_salt: salt.clone(),
                            }),
                            Some(checkpoint),
                            Some(current.public_tree_ref),
                            Some(arkret_sdk::Base64UrlString::new(arkret_sdk::canonical::base64url_encode(arkret_crypto::blob_aead::fresh_stream_nonce_prefix()?)).map_err(anyhow::Error::msg)?),
                        )
                    }
                };
                let suite = arkret_sdk::DigestSuite::Sha256;
                anyhow::ensure!(active(), "attachment target changed");
                fence.check_session_identity()?;
                let object = vault
                    .freeze_attachment(crate::attachments::AttachmentObject {
                        id: salt.as_str().to_owned(),
                        authority: account.authority.clone(),
                        device_id: account.device_id.clone(),
                        scope: scope.clone(),
                        strand_id: strand.clone(),
                        filename: file.name(),
                        long_text: false,
                        input_size: file.size(), input_digest: None, text_prefix: None, line_count: None,
                        media_type: file
                            .content_type()
                            .unwrap_or_else(|| "application/octet-stream".into())
                            .split(';')
                            .next()
                            .unwrap_or("application/octet-stream")
                            .trim()
                            .to_ascii_lowercase(),
                        salt,
                        digest_suite: suite,
                        context,
                        checkpoint,
                        state_tree_ref, nonce_prefix,
                        prepared: None,
                        uploaded: false,
                        submitted_operation: None,
                    })
                    .await?;
                let chunks = crate::state::current_index::AttachmentChunkStore::open(store.read(|s|s.current_index_location()), &account.authority, &account.device_id, &object.id).await?;
                let digest = crate::attachments::file_to_parts(&chunks, &file, suite, active).await?;
                fence.check_session_identity()?;
                anyhow::ensure!(active(), "attachment target changed");
                vault.freeze_attachment_input(&object.id, digest).await?;
            }
            for mut object in vault
                .attachment_objects(&account.device_id, &scope, &strand)
                .await?
            {
                if object.long_text {
                    continue;
                }
                anyhow::ensure!(active(), "attachment session or draft changed");
                let chunks = crate::state::current_index::AttachmentChunkStore::open(store.read(|s|s.current_index_location()), &account.authority, &account.device_id, &object.id).await?;
                if !attachments.get_untracked().iter().any(|a|a.id == object.id) {
                    attachments.revise(|value| value.push(crate::attachments::DraftAttachment {id: object.id.clone(), scope: scope.clone(),
                        content: object.prepared.as_ref().map(|p|p.content.clone()).unwrap_or_else(||arkret_sdk::ContentBlock::new(arkret_sdk::ContentBlockKind::File, object.filename.clone())), pending: !object.uploaded}));
                }
                if object.prepared.is_none() {
                    let prepared = object.prepare(&chunks).await?;
                    object = vault
                        .freeze_prepared_attachment(&object.id, prepared)
                        .await?;
                    chunks.clear("input").await?;
                }
                if !object.uploaded {
                    fence.check_session_identity()?;
                    anyhow::ensure!(active(), "attachment session or draft changed");
                    let gate = crate::attachments::await_attachment_send_gate(&store, &scope, &account.device_id, active).await?;
                    match (&object.context, gate) {
                        (None, crate::mls::send_gate::MlsSendGate::Plaintext) => {},
                        (Some(context), crate::mls::send_gate::MlsSendGate::Encrypted(current)) if context.genesis_event_ref == current.genesis_event_ref => {},
                        _ => anyhow::bail!("attachment classification or Genesis changed; remove it and select the file again"),
                    }
                    anyhow::ensure!(active(), "attachment target changed");
                    crate::attachments::with_target_fence(clients.blob().upload_attachment_object(&object, chunks), active).await?;
                    vault.mark_attachment_uploaded(&object.id).await?;
                }
                fence.check_session_identity()?;
                anyhow::ensure!(active(), "attachment session or draft changed");
                let prepared_content=object.prepared.clone().ok_or_else(||anyhow::anyhow!("missing attachment descriptor"))?.content;
                attachments.revise(|values| {if let Some(draft)=values.iter_mut().find(|a|a.id == object.id){
                    draft.pending = false;
                    draft.content = prepared_content;
                }});

            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if session.session_generation.get_untracked() != generation
            || upload_revision.get_untracked() != run
            || controller.selected_channel.get_untracked() != selected
            || controller.selection_revision.get_untracked() != selection_revision
        {
            return;
        }
        if controller.attachment_target_revision.get_untracked() != target_revision
            || controller.draft.get_untracked() != draft
        {
            {
                let next_value = "Attachment upload: attachment session or target changed".into();
                status.revise(|value| *value = next_value);
            };
            return;
        }
        match result {
            Ok(()) => {
                let next_value =
                    format!("{} attachment(s) ready", attachments.get_untracked().len());
                status.revise(|value| *value = next_value);
            }
            Err(e) => {
                let next_value = format!("Attachment upload: {e:#}");
                status.revise(|value| *value = next_value);
            }
        }
    });
}

/// Cancel the selected durable draft object and revoke its local parts.
pub(super) fn discard_draft_attachment(controller: ChatController, id: String) {
    let revision = controller.attachment_target_revision;
    let next = revision.get_untracked().wrapping_add(1);
    {
        let next_value = next;
        revision.revise(|value| *value = next_value);
    };
    let Some(session) = application_context(controller) else {
        return;
    };
    let account = session.active_account.get_untracked().clone();
    let generation = session.session_generation.get_untracked();
    let attachments = controller.attachments;
    let status = controller.compose_upload_status;
    let store = session.state_store.handle();
    super::super::task::dispatch(async move {
        let result = async {
            let account = account.ok_or_else(|| anyhow::anyhow!("no active attachment account"))?;
            let vault = crate::outbound_store::InksonOutboundStore::open(
                &account.authority,
                crate::outbound_store::OutboundLane::Standard,
            )?;
            vault.discard_attachment(&id, &account.device_id).await?;
            let chunks = crate::state::current_index::AttachmentChunkStore::open(
                store.read(|s| s.current_index_location()),
                &account.authority,
                &account.device_id,
                &id,
            )
            .await?;
            chunks.clear("input").await?;
            chunks.clear("ciphertext").await?;
            if session.session_generation.get_untracked() == generation {
                attachments.revise(|value| value.retain(|a| a.id != id));
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = result {
            {
                let next_value = format!("Attachment removal: {e:#}");
                status.revise(|value| *value = next_value);
            };
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
    super::super::task::dispatch(async move {
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
    let messages = controller.messages;
    let poll_cards = controller.poll_cards;
    let status_msg = controller.status_msg;
    let Some(application) = application_context(controller) else {
        return;
    };
    let state_store = application.state_store.clone();
    super::super::task::dispatch(async move {
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
                messages.revise(|values| {
                    if let Some(found) = values
                        .iter_mut()
                        .find(|candidate| candidate.matches_id_or_protocol(&local_message_id))
                    {
                        found.protocol_message_id = message_ref.clone();
                        found.pending = false;
                        found.failed = false;
                        found.error = None;
                    }
                });
                poll_cards.revise(|values| {
                    if let Some(card) = values
                        .iter_mut()
                        .find(|card| card.message_id == local_message_id)
                        && let Some(message_ref) = message_ref
                    {
                        card.poll_ref = arkret_sdk::MessageId::new(message_ref).ok();
                    }
                });
                {
                    let next_value = "Poll sent".to_owned();
                    status_msg.revise(|value| *value = next_value);
                };
            }
            Err(error) => {
                let error_text = error.display();
                messages.revise(|values| {
                    if let Some(found) = values
                        .iter_mut()
                        .find(|candidate| candidate.matches_id_or_protocol(&local_message_id))
                    {
                        found.pending = false;
                        found.failed = true;
                        found.error = Some(format!("Poll send failed: {error_text}"));
                    }
                });
                {
                    let next_value = format!("Poll send failed: {error_text}");
                    status_msg.revise(|value| *value = next_value);
                };
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
    sidecar_session: Cage<Option<crate::sidecar::HostedSidecarState>>,
    sidecar_route_pending: Cage<bool>,
    route: OwnedAgentSidecarRoute,
) {
    let status_msg = controller.status_msg;
    let Some(application) = application_context(controller) else {
        return;
    };
    let state_store = application.state_store.clone();
    let session_fence = match crate::transport::auth::AuthoringSessionFence::capture() {
        Ok(fence) => fence,
        Err(error) => {
            {
                let next_value = false;
                sidecar_route_pending.revise(|value| *value = next_value);
            };
            {
                let next_value = format!("Private Sidecar message was not sent: {error:#}");
                status_msg.revise(|value| *value = next_value);
            };
            return;
        }
    };
    let draft_fence = PendingSidecarDraftFence::capture(
        controller.draft,
        controller.mention_picker_state,
        controller.selected_channel,
    );
    super::super::task::dispatch(async move {
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
        trace_private_send_stage("private_route_ensure_started");
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
            state_store.clone(),
        )
        .await;
        trace_private_send_stage("private_route_ensure_finished");
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
        trace_private_send_stage(if draft_unchanged {
            "private_route_draft_current"
        } else {
            "private_route_draft_replaced"
        });
        let same_session = session_fence.check().is_ok()
            && crate::presentation::current_context()
                .and_then(|context| context.active_account.try_get().ok().flatten())
                .is_some_and(|active| {
                    active.authority == authority && active.device_id == device_id
                });
        if !same_session {
            trace_private_send_stage("private_route_session_replaced");
            {
                let next_value = false;
                sidecar_route_pending.revise(|value| *value = next_value);
            };
            return;
        }
        if let Err(error) = current_private_mode {
            trace_private_send_stage("private_route_mode_rejected");
            {
                let next_value = false;
                sidecar_route_pending.revise(|value| *value = next_value);
            };
            {
                let next_value = format!("Private Sidecar message was not sent: {error:#}");
                status_msg.revise(|value| *value = next_value);
            };
            return;
        }
        match sidecar_outcome {
            Ok(Some(sidecar)) => {
                let OwnedAgentSidecarEnsureResult {
                    sidecar_id,
                    view: sidecar_view,
                } = sidecar;
                if !draft_unchanged
                    || controller.draft.get_untracked().as_str() != draft_at_send
                    || controller.selected_channel.get_untracked().as_str() != strand_id
                {
                    trace_private_send_stage("private_route_draft_changed_before_access");
                    {
                        let next_value = false;
                        sidecar_route_pending.revise(|value| *value = next_value);
                    };
                    {
                        let next_value =
                            "Private Sidecar ready. The edited draft has not been sent.".to_owned();
                        status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
                let native_mls_ready = state_store
                    .read(|store| crate::sidecar::native_mls_ready_for_view(store, &sidecar_view));
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
                {
                    let next_value = Some(session.clone());
                    sidecar_session.revise(|value| *value = next_value);
                };
                let readiness_fence = PendingSidecarDraftFence::capture(
                    controller.draft,
                    controller.mention_picker_state,
                    controller.selected_channel,
                );
                let ready = wait_for_sidecar_access(
                    || async {
                        let api =
                            crate::transport::auth::authed_api_ready(&base_url, api_token.clone())
                                .await?;
                        let view = api
                            .sdk_http_client()?
                            .agent_sidecar_get(&sidecar_id)
                            .await?;
                        crate::sidecar::validate_agent_sidecar_view(&view)?;
                        anyhow::ensure!(
                            view.sidecar.id == sidecar_id
                                && view.sidecar.realm_id.as_str() == realm_id
                                && view.sidecar.controller_account_id == authority
                                && addressed_agent_ids.iter().all(|id| view
                                    .desired_agent_ids
                                    .iter()
                                    .any(|agent| agent.as_str() == id)),
                            "Private Sidecar access or addressed Agent changed"
                        );
                        let ready = view.access_readiness
                            == arkret_sdk::AgentSidecarAccessReadiness::Ready
                            && view.mls_context.current_controller_device_ready
                            && state_store.read(|store| {
                                crate::sidecar::native_mls_ready_for_view(store, &view)
                            });
                        Ok(ready.then_some(view))
                    },
                    || {
                        session_fence.check()?;
                        anyhow::ensure!(
                            readiness_fence.is_current()
                                && controller.draft.get_untracked().as_str() == draft_at_send
                                && controller.selected_channel.get_untracked().as_str()
                                    == strand_id
                                && sidecar_session
                                    .get_untracked()
                                    .as_ref()
                                    .is_some_and(|open| {
                                        open.trace_id == session.trace_id
                                            && open.controller_account_id == authority
                                            && open.matches_route(&realm_id, &strand_id)
                                    }),
                            "Private Sidecar ready. The edited draft has not been sent"
                        );
                        Ok(())
                    },
                    60,
                )
                .await;
                trace_private_send_stage(if ready.is_ok() {
                    "private_route_access_wait_finished"
                } else {
                    "private_route_access_wait_failed"
                });
                let mode = if ready.is_ok() {
                    require_current_private_targets(
                        &base_url,
                        api_token.clone(),
                        &realm_id,
                        &authority,
                        &mentions,
                        &addressed_agent_ids,
                    )
                    .await
                    .and_then(|_| session_fence.check())
                } else {
                    Ok(())
                };
                let unchanged = readiness_fence.finish()
                    && sidecar_session
                        .get_untracked()
                        .as_ref()
                        .is_some_and(|open| {
                            open.trace_id == session.trace_id
                                && open.controller_account_id == authority
                                && open.matches_route(&realm_id, &strand_id)
                        });
                if session_fence.check_session_identity().is_err() {
                    trace_private_send_stage("private_route_session_replaced_after_access");
                    {
                        let next_value = false;
                        sidecar_route_pending.revise(|value| *value = next_value);
                    };
                    return;
                }
                let ready_view = match ready.and_then(|view| mode.map(|_| view)) {
                    Ok(view) if unchanged => view,
                    outcome => {
                        trace_private_send_stage(if unchanged {
                            "private_route_access_or_mode_rejected"
                        } else {
                            "private_route_draft_or_host_replaced"
                        });
                        {
                            let next_value = false;
                            sidecar_route_pending.revise(|value| *value = next_value);
                        };
                        {
                            let next_value = match outcome {
                                Err(error) => {
                                    format!("Private Sidecar message was not sent: {error:#}")
                                }
                                Ok(_) => {
                                    "Private Sidecar ready. The edited draft has not been sent."
                                        .to_owned()
                                }
                            };
                            status_msg.revise(|value| *value = next_value);
                        };
                        return;
                    }
                };
                let mut session = session;
                session.access_readiness = ready_view.access_readiness;
                session.pending_access_reconciliations = ready_view.pending_access_reconciliations;
                session.mls_context = ready_view.mls_context;
                session.native_mls_ready = true;
                {
                    let next_value = Some(session.clone());
                    sidecar_session.revise(|value| *value = next_value);
                };
                {
                    let next_value = false;
                    sidecar_route_pending.revise(|value| *value = next_value);
                };
                let source_event_id = latest_source_event_anchor(
                    &controller.messages.get_untracked(),
                    &realm_id,
                    &strand_id,
                );
                trace_private_send_stage("private_route_submit_dispatched");
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
            Ok(None) => {
                let next_value =
                    "Could not resolve an owned agent for the private sidecar.".to_owned();
                status_msg.revise(|value| *value = next_value);
            }
            Err(error) => {
                let next_value = format!("Could not open private AI sidecar: {error:#}");
                status_msg.revise(|value| *value = next_value);
            }
        }
        {
            let next_value = false;
            sidecar_route_pending.revise(|value| *value = next_value);
        };
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
    draft: Cage<String>,
    picker: Cage<crate::messaging::mentions::MentionPickerState>,
    strand: Cage<String>,
    versions: Option<(u64, u64, u64)>,
}
impl PendingSidecarDraftFence {
    fn capture(
        draft: Cage<String>,
        picker: Cage<crate::messaging::mentions::MentionPickerState>,
        strand: Cage<String>,
    ) -> Self {
        let versions = draft
            .try_version()
            .ok()
            .zip(picker.try_version().ok())
            .zip(strand.try_version().ok())
            .map(|((draft, picker), strand)| (draft, picker, strand));
        Self {
            draft,
            picker,
            strand,
            versions,
        }
    }
    fn finish(self) -> bool {
        self.is_current()
    }
    fn is_current(&self) -> bool {
        self.versions.is_some()
            && self.versions
                == self
                    .draft
                    .try_version()
                    .ok()
                    .zip(self.picker.try_version().ok())
                    .zip(self.strand.try_version().ok())
                    .map(|((draft, picker), strand)| (draft, picker, strand))
    }
}

async fn wait_for_sidecar_access<T, Read, ReadFuture, Check>(
    mut read: Read,
    mut check: Check,
    attempts: usize,
) -> anyhow::Result<T>
where
    Read: FnMut() -> ReadFuture,
    ReadFuture: std::future::Future<Output = anyhow::Result<Option<T>>>,
    Check: FnMut() -> anyhow::Result<()>,
{
    for attempt in 0..attempts {
        check()?;
        let ready = read().await?;
        check()?;
        if let Some(ready) = ready {
            return Ok(ready);
        }
        if attempt + 1 < attempts {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(2)).await;
        }
    }
    anyhow::bail!("Private Sidecar access did not become ready; the draft has not been sent")
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
    frontier_state: Cage<String>,
    request: PlaintextSendRequest,
) {
    let messages = controller.messages;
    let status_msg = controller.status_msg;
    let chat_draft = controller.draft;
    let attachment_drafts = controller.attachments.get_untracked().clone();
    let mut pending_draft = PendingComposerDraft::new(controller, &request.local_id, &request.body);
    let Some(application) = application_context(controller) else {
        return;
    };
    let state_store = application.state_store.clone();
    // A verified-current refresh can replace the composer send Button.
    // Its in-flight write belongs to the controller's message list.
    super::super::task::dispatch(async move {
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
        messages.revise(|values| {
            if let Some(found) = values
                .iter_mut()
                .find(|candidate| candidate.matches_id_or_protocol(&local_id))
            {
                found.mentions = mentions.clone();
            }
        });
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
                fail_optimistic_send_row(messages, &local_id, format!("send failed: {error:#}"));
                {
                    let next_value = format!("send failed: {error:#}");
                    status_msg.revise(|value| *value = next_value);
                };
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
                fail_optimistic_send_row(messages, &local_id, format!("send failed: {error:#}"));
                {
                    let next_value = format!("send failed: {error:#}");
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
        };
        let local_operation_id =
            crate::operation::LocalOperationId::from_holder_key(local_id.clone()).to_string();
        let api = match authed_api_with_sync(&base_url, api_token, wait_for) {
            Ok(api) => api,
            Err(error) => {
                fail_optimistic_send_row(messages, &local_id, format!("send failed: {error:#}"));
                {
                    let next_value = format!("send failed: {error:#}");
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
        };
        let scope =
            match arkret_sdk::RealmId::new(realm_id.clone()).and_then(|realm_id| match circle_id {
                Some(circle_id) => arkret_sdk::CircleId::new(circle_id).map(|circle_id| {
                    arkret_sdk::ScopeRef::Circle {
                        realm_id,
                        circle_id,
                    }
                }),
                None => Ok(arkret_sdk::ScopeRef::Realm { realm_id }),
            }) {
                Ok(scope) => scope,
                Err(error) => {
                    fail_optimistic_send_row(messages, &local_id, format!("send failed: {error}"));
                    {
                        let next_value = format!("send failed: {error}");
                        status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
            };
        let content = match crate::attachments::compose_draft_attachments(
            content,
            &attachment_drafts,
            &scope,
        ) {
            Ok(content) => content,
            Err(error) => {
                fail_optimistic_send_row(messages, &local_id, format!("send failed: {error:#}"));
                {
                    let next_value = format!("send failed: {error:#}");
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
        };
        let content_for_store = serde_json::to_value(&content).unwrap_or(serde_json::Value::Null);
        // The §4.5 mention-routing sidecar exists so an encrypted Realm can
        // route a notification without revealing the mentioned DID. A
        // plaintext send already carries `mentions` in the clear, so it gets
        // no sidecar.
        let mention_values_for_store = mention_nodes_to_values(&mentions);
        match send_ordinary_chat_message(
            &api,
            state_store.handle(),
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
                pending_draft.record_send_status(resp.status);
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
                    Ok(raw_operation) => state_store.write(|value| {
                        value.append_raw_operation(
                            local_operation_id.clone(),
                            Some(realm_id),
                            raw_operation,
                        )
                    }),
                    Err(error) => tracing::error!(
                        %error,
                        event_id = %resp.event_id,
                        "accepted chat operation could not be cached"
                    ),
                }
                messages.revise(|values| {
                    if let Some(found) = values
                        .iter_mut()
                        .find(|candidate| candidate.matches_id_or_protocol(&local_id))
                    {
                        found.id = resp.event_id.clone();
                        found.pending = resp.status != garth::SendQueueStatus::Committed;
                        found.failed = false;
                        found.error = None;
                    }
                });
                if resp.status == garth::SendQueueStatus::Committed {
                    {
                        let next_value = resp.event_id.clone();
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
                    let next_value = if resp.status == garth::SendQueueStatus::Committed {
                        "Message sent".to_owned()
                    } else {
                        "Message queued; waiting for server confirmation".to_owned()
                    };
                    status_msg.revise(|value| *value = next_value);
                };
            }
            Err(failure) => {
                pending_draft.record_failure(&failure);
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
}

/// Show exactly what stopped one message, and leave the row in the state that
/// matches it.
///
/// A submission whose result is unknown stays pending: the exact signed bytes
/// are durable and the drain owns them, so marking the bubble failed would
/// invite the user to author a duplicate of a message that may already exist.
pub(super) fn present_chat_send_failure(
    messages: Cage<Vec<ChatMessage>>,
    status_msg: Cage<String>,
    chat_draft: Cage<String>,
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
        {
            let next_value = message;
            status_msg.revise(|value| *value = next_value);
        };
        return;
    }
    if matches!(
        failure,
        garth::MessageAuthoringFailure::Refused { code, .. } if code == "space_membership_denied"
    ) {
        messages.revise(|value| value.retain(|candidate| candidate.id != local_id));
        if chat_draft.get().trim().is_empty() {
            {
                let next_value = body.to_owned();
                chat_draft.revise(|value| *value = next_value);
            };
        }
        {
            let next_value = message;
            status_msg.revise(|value| *value = next_value);
        };
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
fn fail_optimistic_send_row(messages: Cage<Vec<ChatMessage>>, local_id: &str, error: String) {
    messages.revise(|values| {
        if let Some(found) = values
            .iter_mut()
            .find(|candidate| candidate.matches_id_or_protocol(local_id))
        {
            found.pending = false;
            found.failed = true;
            found.error = Some(error);
        }
    });
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
    let Some(application) = application_context(controller) else {
        return;
    };
    let hosted = application.hosted_sidecar;
    send_sidecar_message_with_hosted(controller, hosted, request);
}

fn send_sidecar_message_with_hosted(
    controller: ChatController,
    hosted: Cage<Option<crate::sidecar::HostedSidecarState>>,
    request: SidecarSendRequest,
) {
    let messages = controller.messages;
    let status_msg = controller.status_msg;
    let chat_draft = controller.draft;
    let attachment_drafts = controller.attachments.get_untracked().clone();
    let draft_attachments = controller.attachments;
    let picker = controller.mention_picker_state;
    let picker_at_send = picker.get_untracked().clone();
    let sending = controller.sidecar_send_pending;
    if sending.get_untracked() {
        trace_private_send_stage("private_submit_already_pending");
        return;
    }
    let authoring_fence = match crate::transport::auth::AuthoringSessionFence::capture() {
        Ok(fence)
            if crate::presentation::current_context()
                .and_then(|context| context.active_account.try_get().ok().flatten())
                .is_some_and(|active| {
                    active.authority == request.authority && active.device_id == request.device_id
                }) =>
        {
            fence
        }
        _ => {
            trace_private_send_stage("private_submit_session_replaced");
            {
                let next_value =
                    "Private Sidecar message was not sent: account session changed".to_owned();
                status_msg.revise(|value| *value = next_value);
            };
            return;
        }
    };
    {
        let next_value = true;
        sending.revise(|value| *value = next_value);
    };
    messages.revise(|value| {
        value.push(ChatMessage {
            protocol_content: None,
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
        })
    });
    let reply_to = controller.reply_to_message;
    {
        let next_value = None;
        reply_to.revise(|value| *value = next_value);
    };
    let Some(application) = application_context(controller) else {
        return;
    };
    let state_store = application.state_store.clone();
    super::super::task::dispatch(async move {
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
        trace_private_send_stage("private_submit_started");
        let resolved_mentions = mentions;
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
                            application.clone(),
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
                            &attachment_drafts,
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
                draft_attachments.revise(|value| {
                    value.retain(|a| !attachment_drafts.iter().any(|used| used.id == a.id))
                });
                trace_private_send_stage(if routed.history_pending.is_some() {
                    "private_submit_accepted_history_pending"
                } else {
                    "private_submit_accepted_history_verified"
                });
                messages.revise(|values| {
                    if let Some(found) = values
                        .iter_mut()
                        .find(|candidate| candidate.matches_id_or_protocol(&local_id))
                    {
                        found.id = routed.event_id;
                        found.pending = false;
                        found.failed = false;
                        found.error = None;
                        found.mentions = resolved_mentions;
                    }
                });
                {
                    let next_value = match routed.history_pending {
                        Some(reason) => format!(
                            "Private Sidecar message accepted; awaiting verified history: {reason}"
                        ),
                        None => "Private Sidecar message sent".to_owned(),
                    };
                    status_msg.revise(|value| *value = next_value);
                };
                let open_snapshot = hosted.get_untracked().clone();
                if let Some(mut open) = open_snapshot.filter(|open| {
                    authoring_fence.check_session_identity().is_ok()
                        && open.sidecar_id == session.sidecar_id
                        && open.controller_account_id == session.controller_account_id
                        && open.matches_route(&session.source_realm_id, &session.source_strand_id)
                }) {
                    open.addressed_agent_ids = addressed_agent_ids;
                    if hosted.get_untracked().as_ref() != Some(&open) {
                        {
                            let next_value = Some(open);
                            hosted.revise(|value| *value = next_value);
                        };
                    }
                }
                if authoring_fence.check_session_identity().is_ok()
                    && chat_draft.get_untracked().as_str() == draft_at_send
                    && picker.get_untracked() == picker_at_send
                    && controller.selected_channel.get_untracked() == session.source_strand_id
                    && hosted.get_untracked().as_ref().is_some_and(|open| {
                        open.sidecar_id == session.sidecar_id
                            && open.controller_account_id == session.controller_account_id
                            && open
                                .matches_route(&session.source_realm_id, &session.source_strand_id)
                    })
                {
                    {
                        let next_value = String::new();
                        chat_draft.revise(|value| *value = next_value);
                    };
                    picker.revise(|value| value.clear());
                }
            }
            Err(error) => {
                trace_private_send_stage("private_submit_failed");
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &local_id,
                    &body,
                    format!("Private Sidecar message was not sent: {error:#}"),
                )
            }
        }
        {
            let next_value = false;
            sending.revise(|value| *value = next_value);
        };
    });
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
    pub backup_trigger_signal: Option<Cage<bool>>,
}

pub(super) fn send_encrypted_message(
    controller: ChatController,
    frontier_state: Cage<String>,
    request: EncryptedSendRequest,
) {
    let messages = controller.messages;
    let status_msg = controller.status_msg;
    let chat_draft = controller.draft;
    let attachment_drafts = controller.attachments.get_untracked().clone();
    let selection_revision = controller.selection_revision.get_untracked();
    let selected = controller.selected_channel.get_untracked().clone();
    let mut pending_draft =
        PendingComposerDraft::new(controller, &request.message_id, &request.body);
    let Some(session) = application_context(controller) else {
        return;
    };
    let session_generation = session.session_generation.get_untracked();
    let state_store = session.state_store.clone();
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
    let device_for_cache = did.clone();
    let base_for_backup_trigger = base.clone();
    let token_for_backup_trigger = api_token.clone();
    let actor_for_backup_trigger = actor.clone();
    super::super::task::dispatch(async move {
        messages.revise(|values| {
            if let Some(found) = values
                .iter_mut()
                .find(|candidate| candidate.id == message_id)
            {
                found.mentions = mentions.clone();
            }
        });
        if let Err(error) = crate::transport::agent_interaction::require_public_targets(
            &base,
            api_token.clone(),
            &realm,
            shared_agent_targets.clone(),
        )
        .await
        {
            fail_optimistic_chat_send(
                messages,
                chat_draft,
                status_msg,
                &message_id,
                &body,
                format!("Send blocked: {error:#}"),
            );
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
        let scope = match arkret_sdk::RealmId::new(realm.clone()).and_then(|realm_id| {
            match circle_id.as_ref() {
                Some(id) => arkret_sdk::CircleId::new(id.clone()).map(|circle_id| {
                    arkret_sdk::ScopeRef::Circle {
                        realm_id,
                        circle_id,
                    }
                }),
                None => Ok(arkret_sdk::ScopeRef::Realm { realm_id }),
            }
        }) {
            Ok(scope) => scope,
            Err(e) => {
                {
                    let next_value = e.to_string();
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
        };
        let content_api = match authed_api_with_sync(&base, api_token.clone(), wait_for.clone()) {
            Ok(api) => api,
            Err(e) => {
                {
                    let next_value = e.to_string();
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
        };
        let target_active = || {
            controller.selection_revision.get_untracked() == selection_revision
                && controller.selected_channel.get_untracked() == selected
                && session.session_generation.get_untracked() == session_generation
        };
        let mut secure_content_block = match crate::attachments::with_target_fence(
            crate::attachments::private_message_body(
                &content_api,
                state_store.handle(),
                &authority_for_sidecar,
                &did,
                &scope,
                &strand_id,
                &message_id,
                &body,
            ),
            target_active,
        )
        .await
        {
            Ok(content) => content,
            Err(e) => {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id,
                    &body,
                    format!("Send Secure: {e:#}"),
                );
                return;
            }
        };
        secure_content_block = match crate::attachments::compose_draft_attachments(
            secure_content_block,
            &attachment_drafts,
            &scope,
        ) {
            Ok(content) => content,
            Err(e) => {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id,
                    &body,
                    e.to_string(),
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
            &state_store.handle(),
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
        super::super::task::dispatch(async move {
            if let Err(error) = crate::transport::agent_interaction::require_public_targets(
                &base,
                api_token,
                &realm_for_record,
                shared_agent_targets,
            )
            .await
            {
                fail_optimistic_chat_send(
                    messages,
                    chat_draft,
                    status_msg,
                    &message_id_for_failure,
                    &body_for_restore,
                    format!("Send blocked: {error:#}"),
                );
                return;
            }
            // Shared submit: forced ak.mls.commit first
            // (persist-on-accept snapshot + §7.10 backup
            // schedule + move record), then the encrypted
            // ak.message.create.
            let outcome = crate::views::secure_send::submit_secure_send(
                session.clone(),
                &api,
                &state_store.handle(),
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
                    pending_draft.record_failure(&failure);
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
            pending_draft.record_send_status(match resp_status.as_str() {
                "committed" => garth::SendQueueStatus::Committed,
                "queued" => garth::SendQueueStatus::Queued,
                "forwarding" => garth::SendQueueStatus::Forwarding,
                "rejected" => garth::SendQueueStatus::Rejected,
                "cancelled" => garth::SendQueueStatus::Cancelled,
                _ => garth::SendQueueStatus::Failed,
            });
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
            // Acceptance belongs to the original account and device even when
            // the UI session was replaced while submission awaited the Station.
            if session.session_generation.get_untracked() != session_generation
                || !session
                    .active_account
                    .get_untracked()
                    .as_ref()
                    .is_some_and(|account| {
                        account.authority == authority_for_sidecar
                            && account.device_id == device_for_cache
                    })
                || state_store.read(|value| value.active_authority()).as_ref()
                    != Some(&authority_for_sidecar)
            {
                return;
            }
            {
                state_store.write(|store| {
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
                });
            }
            // The optimistic row is allowed to settle
            // only after both durable stores contain
            // the accepted message identity and the
            // author-owned plaintext. A hard reload
            // immediately after the UI reports success
            // must not race either IndexedDB write.
            let durable_result: anyhow::Result<()> = async {
                let account_barrier = state_store.read(|value| value.begin_durable_flush())?;
                super::super::persist_chat_cache_after_account_barrier(
                    state_store.clone(),
                    &authority_for_sidecar,
                    account_barrier.wait(),
                    || {
                        session.session_generation.get_untracked() == session_generation
                            && session.active_account.get_untracked().as_ref().is_some_and(
                                |account| {
                                    account.authority == authority_for_sidecar
                                        && account.device_id == device_for_cache
                                },
                            )
                    },
                    crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
                )
                .await
            }
            .await;
            if let Err(error) = durable_result {
                let message = format!(
                    "Encrypted message was accepted, but local recovery state could not be persisted: {error}"
                );
                messages.revise(|values| {
                    if let Some(found) = values
                        .iter_mut()
                        .find(|candidate| candidate.matches_id_or_protocol(&message_id_for_lookup))
                    {
                        found.pending = false;
                        found.failed = true;
                        found.error = Some(message.clone());
                    }
                });
                {
                    let next_value = message;
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
            // BUG A (X9): clear the optimistic bubble's
            // `pending` spinner now that the server accepted
            // the encrypted message (mirrors the plaintext
            // path). Reconcile the local id to the server
            // event_id so the synced copy dedups against this
            // echo.
            messages.revise(|values| {
                if let Some(found) = values
                    .iter_mut()
                    .find(|candidate| candidate.matches_id_or_protocol(&message_id_for_lookup))
                {
                    found.id = resp_event_id.clone();
                    found.protocol_message_id = Some(protocol_message_id.clone());
                    found.pending = resp_status != "committed";
                    found.failed = false;
                    found.error = None;
                }
            });
            if resp_status == "committed" {
                {
                    let next_value = resp_event_id.clone();
                    frontier_state.revise(|value| *value = next_value);
                };
            }
            {
                let next_value = if resp_status == "committed" {
                    "Encrypted message sent".to_owned()
                } else {
                    "Encrypted message queued; waiting for server confirmation".to_owned()
                };
                status_msg.revise(|value| *value = next_value);
            };
            crate::components::schedule_mls_recovery_backups_after_encrypted_write(
                session.clone(),
                base_for_backup_trigger.clone(),
                token_for_backup_trigger.clone(),
                authority_for_sidecar.clone(),
                actor_for_backup_trigger.clone(),
                device_for_sidecar_backup.to_string(),
                state_store.handle(),
            );

            // X11.2 — first-write trigger. After this
            // encrypted send landed, auto-back up the
            // account secret when possible; otherwise
            // fall back to the prompt. Best-effort.
            if let Some(signal) = backup_trigger_signal {
                crate::components::maybe_auto_backup_mls_after_encrypted_write(
                    session.clone(),
                    base_for_backup_trigger.clone(),
                    token_for_backup_trigger.clone(),
                    authority_for_sidecar.clone(),
                    actor_for_backup_trigger.clone(),
                    device_for_sidecar_backup.to_string(),
                    state_store.handle(),
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

fn application_context(
    controller: ChatController,
) -> Option<Rc<crate::presentation::InksonContext>> {
    let context = crate::presentation::current_context();
    if context.is_none() {
        let _ = controller
            .status_msg
            .try_revise(|value| *value = "The application session is unavailable.".into());
    }
    context
}

#[cfg(test)]
mod pending_sidecar_draft_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    type Signals = (
        Cage<String>,
        Cage<crate::messaging::mentions::MentionPickerState>,
        Cage<String>,
        Cage<bool>,
    );
    type Control = Rc<RefCell<Option<Signals>>>;

    fn harness(scope: &Scope, control: Control) {
        let draft = scope.cage("original private draft".to_owned());
        let picker = scope.cage(crate::messaging::mentions::MentionPickerState::new());
        let strand = scope.cage("source strand".to_owned());
        let background_ready = scope.cage(false);
        *control.borrow_mut() = Some((draft, picker, strand, background_ready));
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
        let app = glory::ui::App::memory();
        harness(app.scope(), control.clone());
        let (draft, picker, strand, background) = control.borrow().unwrap();
        {
            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            background.revise(|value| *value = true);
            assert!(
                fence.finish(),
                "background readiness must not cancel the frozen draft"
            );

            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            {
                let next_value = "ordinary edited message".into();
                draft.revise(|value| *value = next_value);
            };
            {
                let next_value = "original private draft".into();
                draft.revise(|value| *value = next_value);
            };
            assert!(
                !fence.finish(),
                "restoring the same text cannot restore the old Send authorization"
            );

            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            picker.revise(|value| value.clear());
            assert!(
                !fence.finish(),
                "mention binding writes invalidate delayed Send"
            );

            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            {
                let next_value = "different source".into();
                strand.revise(|value| *value = next_value);
            };
            {
                let next_value = "source strand".into();
                strand.revise(|value| *value = next_value);
            };
            assert!(
                !fence.finish(),
                "returning to the same Strand cannot resume an old Send"
            );

            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            assert!(fence.finish());
        };
    }

    #[tokio::test]
    async fn pending_access_resumes_only_the_unchanged_private_send() {
        for edit_during_wait in [false, true] {
            let control = Rc::new(RefCell::new(None));
            let app = glory::ui::App::memory();
            harness(app.scope(), control.clone());
            let (draft, picker, strand, background) = control.borrow().unwrap();
            let fence = PendingSidecarDraftFence::capture(draft, picker, strand);
            let reads = std::cell::Cell::new(0);
            let result = wait_for_sidecar_access(
                || {
                    let call = reads.get() + 1;
                    reads.set(call);
                    {
                        background.revise(|value| *value = true);
                        if call == 2 && edit_during_wait {
                            {
                                let next_value = "edited ordinary draft".into();
                                draft.revise(|value| *value = next_value);
                            };
                            {
                                let next_value = "original private draft".into();
                                draft.revise(|value| *value = next_value);
                            };
                        }
                    };
                    std::future::ready(Ok((call == 2).then_some(true)))
                },
                || {
                    anyhow::ensure!(fence.is_current(), "draft intent changed");
                    Ok(())
                },
                2,
            )
            .await;
            assert_eq!(reads.get(), 2);
            if edit_during_wait {
                assert!(
                    result.is_err(),
                    "readiness must not revive a revoked Send intent"
                );
                assert!(!fence.finish());
            } else {
                assert!(result.unwrap());
                assert!(
                    fence.finish(),
                    "background access preparation preserves intent"
                );
            }
        }
        let reads = std::cell::Cell::new(0);
        let timeout = wait_for_sidecar_access(
            || {
                reads.set(reads.get() + 1);
                std::future::ready(Ok::<Option<bool>, anyhow::Error>(None))
            },
            || Ok(()),
            1,
        )
        .await;
        assert!(timeout.is_err());
        assert_eq!(reads.get(), 1, "access waits have a finite read budget");
    }
}
