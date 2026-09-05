//! Composer writes, out of the `rsx!` and named.
//!
//! Each of these ran as an inline `spawn(async move { … })` inside an
//! `onclick` or `ondrop`. Several ran twice: the compact and wide composer
//! layouts each carried their own byte-identical copy of the poll send and of
//! the owned-agent sidecar route, so a fix to one could miss the other. There
//! is one copy of each here, and the layouts call it.

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
                                .mls_snapshot_for_scope_and_group(&native_scope, group_id.as_str())
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
