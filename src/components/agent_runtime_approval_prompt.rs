use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;
use arkret_sdk::{DidCoreId, DidUrl, Hash, KeyState, NotificationId, OpaqueLocalId};
use dioxus::prelude::*;

use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::views::agents::{
    build_agent_key_authorization_for_pairing, build_requested_scope_disclosure_for_pairing,
    into_agent_key_pair_request, parse_runtime_key_approval_request,
    runtime_key_pairing_error_message, summarize_runtime_key_approval_request,
};
use crate::views::helpers::short_protocol_id;

const APPROVAL_FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(30);
const APPROVAL_FALLBACK_MAX_INTERVAL: Duration = Duration::from_secs(60);

fn approval_scope_summary(scope: &arkret_sdk::AgentKeyScope) -> Vec<String> {
    let mut labels = Vec::new();
    for action in &scope.actions {
        let key = match action.as_str() {
            "ak.event.read" => "agent_runtime.permission_read",
            "ak.message.create" => "agent_runtime.permission_post",
            "ak.reaction.add" => "agent_runtime.permission_react",
            "ak.agent.draft.propose" | "ak.agent.action.request" => {
                "agent_runtime.permission_draft"
            }
            "ak.strand.create" | "ak.strand.update" | "ak.relation.create" => {
                "agent_runtime.permission_organize"
            }
            "ak.self.committed_event.read.scan.v1"
            | "ak.self.committed_event.stream.subscribe.v1" => "agent_runtime.permission_sync",
            "ak.self.events.command.submit.v1" => "agent_runtime.permission_submit",
            "ak.self.keys.keypackages.upload.create.v1"
            | "ak.self.keys.keypackages.command.consume.v1"
            | "ak.self.keys.keypackages.command.revoke.v1"
            | "ak.self.device_messages.read.list.v1"
            | "ak.self.device_messages.command.ack.v1" => "agent_runtime.permission_encrypted",
            "ak.self.signal.command.send.v1" => "agent_runtime.permission_presence",
            "ak.self.committed_event.resource.get.v1" => "agent_runtime.permission_resources",
            _ => "",
        };
        let label = if key.is_empty() {
            crate::i18n::tr_args(
                "agent_runtime.permission_other",
                &[("action", action.clone())],
            )
        } else {
            crate::i18n::tr(key)
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if scope
        .constraints
        .iter()
        .any(|constraint| constraint.controller_approval_required == Some(true))
    {
        labels.push(crate::i18n::tr("agent_runtime.permission_review"));
    }
    labels
}

#[derive(Clone, Debug)]
struct PendingAgentRuntimeApproval {
    notification_id: Option<NotificationId>,
    request_key: OpaqueLocalId,
    agent_id: DidCoreId,
    display_name: String,
    agent_slug: String,
    pairing_code: String,
    pairing_expires_at: String,
    verification_method: DidUrl,
    public_key_fingerprint: Hash,
    key_state: KeyState,
    request_json: String,
    replacement: bool,
}

#[component]
pub fn AgentRuntimeApprovalPrompt(
    token: Signal<String>,
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    server_description: Signal<Option<arkret_sdk::ServiceDescribe>>,
) -> Element {
    let mut pending = use_signal(|| None::<PendingAgentRuntimeApproval>);
    let mut handled = use_signal(HashSet::<OpaqueLocalId>::new);
    let mut status = use_signal(String::new);
    let mut diagnostic = use_signal(String::new);
    let mut prepared = use_signal(|| None::<(OpaqueLocalId, arkret_sdk::AgentKeyPairRequestBody)>);
    let mut approving = use_signal(|| false);
    let state_store = crate::app::SessionContext::get().state_store;
    let active_account = crate::app::SessionContext::get().active_account;
    let mut owned_agents_rev = crate::app::SessionContext::get().owned_agents_rev;

    {
        let token = token;
        use_effect(move || {
            let projection = state_store.read().notification_projection();
            let open = projection
                .iter()
                .filter_map(agent_runtime_approval_notification)
                .collect::<Vec<_>>();
            let prompt_notification_closed = pending.read().as_ref().is_some_and(|request| {
                request
                    .notification_id
                    .as_ref()
                    .is_some_and(|notification_id| {
                        !open
                            .iter()
                            .any(|notification| &notification.notification_id == notification_id)
                    })
            });
            if prompt_notification_closed {
                pending.set(None);
                approving.set(false);
            }
            if pending.read().is_some() {
                return;
            }
            let Some(notification) = open
                .into_iter()
                .find(|notification| !handled.read().contains(&notification.approval_request_id))
            else {
                return;
            };
            let Some(account) = active_account() else {
                return;
            };
            let server_url = account.server_url.to_string();
            let api_token = token();
            if api_token.trim().is_empty() {
                return;
            }
            spawn(async move {
                match fetch_agent_runtime_approval(&server_url, api_token, notification).await {
                    Ok(Some(request)) => {
                        tracing::info!(agent_id = %request.agent_id, "agent runtime approval discovered through account notification");
                        status.set(String::new());
                        diagnostic.set(String::new());
                        pending.set(Some(request));
                    }
                    Ok(None) => {}
                    Err(error) => tracing::warn!(
                        error = %error.display_diagnostic(),
                        "agent runtime approval notification refresh failed"
                    ),
                }
            });
        });
    }

    {
        let token = token;
        use_future(move || async move {
            loop {
                let has_prompt = pending.read().is_some();
                if has_prompt {
                    let prompt_expired = pending.read().as_ref().is_some_and(approval_has_expired);
                    if prompt_expired {
                        pending.set(None);
                        approving.set(false);
                        status.set(String::new());
                        diagnostic.set(String::new());
                    }
                    crate::runtime_helpers::sleep_for(APPROVAL_FALLBACK_POLL_INTERVAL).await;
                    continue;
                }

                if !fallback_poll_environment_ready()
                    || !approval_fallback_allowed(server_description.read().as_ref())
                {
                    crate::runtime_helpers::sleep_for(APPROVAL_FALLBACK_POLL_INTERVAL).await;
                    continue;
                }

                let api_token = token();
                if api_token.trim().is_empty() {
                    crate::runtime_helpers::sleep_for(APPROVAL_FALLBACK_POLL_INTERVAL).await;
                    continue;
                }

                let Some(account) = active_account() else {
                    crate::runtime_helpers::sleep_for(APPROVAL_FALLBACK_POLL_INTERVAL).await;
                    continue;
                };
                let server_url = account.server_url.to_string();
                let handled_keys = handled.read().clone();
                let failed = match fetch_pending_agent_runtime_approval(
                    &server_url,
                    api_token,
                    handled_keys,
                )
                .await
                {
                    Ok(Some(request)) => {
                        tracing::info!(agent_id = %request.agent_id, "agent runtime approval discovered through unsupported-notification fallback");
                        status.set(String::new());
                        diagnostic.set(String::new());
                        pending.set(Some(request));
                        false
                    }
                    Ok(None) => {
                        status.set(String::new());
                        diagnostic.set(String::new());
                        false
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err.display_diagnostic(),
                            "agent runtime approval polling failed"
                        );
                        true
                    }
                };

                crate::runtime_helpers::sleep_for(approval_fallback_delay(failed)).await;
            }
        });
    }

    if active_account().is_none() || token().trim().is_empty() {
        return rsx! {};
    }

    let Some(request) = pending() else {
        return rsx! {};
    };

    let agent_label = if request.display_name.trim().is_empty() {
        request.agent_slug.clone()
    } else {
        request.display_name.clone()
    };
    let agent_id_label = request.agent_id.to_string();
    let verification_label = request.verification_method.to_string();
    let fingerprint_label = request.public_key_fingerprint.to_string();
    let station_label = request
        .key_state
        .controller_account_id
        .station_id
        .to_string();
    let scope_label =
        serde_json::to_string_pretty(&request.key_state.requested_scope).unwrap_or_default();
    let permissions = approval_scope_summary(&request.key_state.requested_scope);
    let expiry_label = chrono::DateTime::parse_from_rfc3339(&request.pairing_expires_at)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| request.pairing_expires_at.clone());
    let code_label = format!(
        "{} {}",
        &request.pairing_code[..4],
        &request.pairing_code[4..]
    );
    let supersedes_label = request
        .key_state
        .active_authorizations
        .iter()
        .map(|authorization| {
            format!(
                "{} / {}",
                authorization.key_id, authorization.authorized_event_ref
            )
        })
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    let status_value = status();
    let diagnostic_value = diagnostic();
    let busy = approving();

    let dismiss_key = request.request_key.clone();
    let dismiss_button_key = request.request_key.clone();
    let approve_request = request.clone();

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    handled.write().insert(dismiss_key.clone());
                    pending.set(None);
                    status.set(String::new());
                    diagnostic.set(String::new());
                    approving.set(false);
                }
            },
            "data-testid": "agent-runtime-approval-modal",
            "aria-labelledby": "agent-runtime-approval-title",
            "aria-label": crate::i18n::tr("agent_runtime.aria_label"),
            div { class: "modal event agent-runtime-approval-dialog",
                div { class: "modal-head event-head",
                    h3 { id: "agent-runtime-approval-title", {crate::i18n::tr("agent_runtime.title")} }
                    span { class: "muted", {crate::i18n::tr("agent_runtime.subtitle")} }
                }
                div { class: "modal-body",
                    p { class: "muted",
                        {crate::i18n::tr("agent_runtime.body")}
                    }
                    if request.replacement {
                        p { class: "warning", {crate::i18n::tr("agent_runtime.replacement_warning")} }
                    }
                    div {
                        class: "device-pair-approval-device",
                        "data-testid": "agent-runtime-approval-agent",
                        "data-agent-id": "{request.agent_id}",
                        strong { "{agent_label}" }
                        if !request.agent_slug.trim().is_empty() && request.agent_slug != agent_label {
                            span { class: "muted",
                                {crate::i18n::tr_args("agent_runtime.slug", &[("slug", request.agent_slug.clone())])}
                            }
                        }
                    }
                    div { class: "device-pair-approval-code-block",
                        span { class: "muted", {crate::i18n::tr("agent_runtime.compare_code")} }
                        strong {
                            class: "device-pair-approval-code mono",
                            "data-testid": "agent-runtime-approval-code",
                            "{code_label}"
                        }
                        span { class: "muted",
                            {crate::i18n::tr_args("agent_runtime.pairing_expires", &[("time", expiry_label)])}
                        }
                    }
                    section { class: "agent-approval-permissions",
                        strong { {crate::i18n::tr("agent_runtime.permissions")} }
                        ul {
                            for permission in permissions {
                                li { "{permission}" }
                            }
                        }
                        p { class: "muted", {crate::i18n::tr("agent_runtime.scope_ceiling")} }
                        p { class: "muted", {crate::i18n::tr("agent_runtime.until_revoked")} }
                    }
                    details { class: "agent-approval-details",
                        summary { {crate::i18n::tr("agent_runtime.technical_details")} }
                        dl {
                            dt { {crate::i18n::tr("agent_runtime.agent_id")} }
                            dd { class: "mono", "{agent_id_label}" }
                            dt { {crate::i18n::tr("agent_runtime.station")} }
                            dd { class: "mono", "{station_label}" }
                            dt { {crate::i18n::tr("agent_runtime.runtime_key")} }
                            dd { class: "mono", "data-testid": "agent-runtime-approval-runtime-key", "{fingerprint_label}" }
                            dt { {crate::i18n::tr("agent_runtime.verification_method")} }
                            dd { class: "mono", "{verification_label}" }
                            dt { {crate::i18n::tr("agent_runtime.requested_scope")} }
                        }
                        pre { "{scope_label}" }
                        if !supersedes_label.is_empty() {
                            p { {crate::i18n::tr("agent_runtime.replaced_authorizations")} }
                            pre { "{supersedes_label}" }
                        }
                    }
                    if !status_value.is_empty() {
                        div { class: "muted", "data-testid": "agent-runtime-approval-status", "{status_value}" }
                    }
                    if !diagnostic_value.is_empty() {
                        details { class: "agent-approval-details",
                            summary { {crate::i18n::tr("agent_runtime.error_details")} }
                            pre { "{diagnostic_value}" }
                        }
                    }
                }
                div { class: "modal-foot actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-runtime-approval-reject-rotate",
                        disabled: busy,
                        onclick: {
                            let reject_agent_id = request.agent_id.clone();
                            move |_| {
                                let Some(account) = active_account() else {
                                    status.set(crate::i18n::tr("agent_runtime.err_no_account"));
                                    return;
                                };
                                let server_url = account.server_url.to_string();
                                let api_token = token();
                                let agent_id = reject_agent_id.clone();
                                approving.set(true);
                                status.set(crate::i18n::tr("agent_runtime.rejecting"));
                                spawn(async move {
                                    let result = with_authed_sdk_client(&server_url, api_token, move |http| {
                                        let agent_id = agent_id.clone();
                                        async move {
                                            http.agent_renew_pairing(
                                                agent_id.as_str(),
                                                &arkret_models_collaboration::agent_operations::AgentRenewPairingRequestBody::default(),
                                            )
                                            .await
                                            .map_err(anyhow::Error::from)
                                        }
                                    })
                                    .await;
                                    approving.set(false);
                                    match result {
                                        Ok(_) => {
                                            pending.set(None);
                                            status.set(crate::i18n::tr("agent_runtime.rejected"));
                                        }
                                        Err(error) => status.set(crate::i18n::tr_args(
                                            "agent_runtime.err_rotate_failed",
                                            &[("error", error.display())],
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("agent_runtime.reject_rotate")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-runtime-approval-dismiss",
                        disabled: busy,
                        onclick: move |_| {
                            handled.write().insert(dismiss_button_key.clone());
                            pending.set(None);
                            status.set(String::new());
                            diagnostic.set(String::new());
                            approving.set(false);
                        },
                        {crate::i18n::tr("agent_runtime.dismiss")}
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "agent-runtime-approval-approve",
                        disabled: busy,
                        onclick: move |_| {
                            if approving() {
                                return;
                            }
                            let controller = principal_id();
                            if controller.is_none() {
                                status.set(crate::i18n::tr("agent_runtime.err_no_account"));
                                return;
                            };
                            let Some(account) = active_account() else {
                                status.set(crate::i18n::tr("agent_runtime.err_no_account"));
                                return;
                            };
                            let server_url = account.server_url.to_string();
                            let controller_did = account.did().to_string();
                            let body = match parse_runtime_key_approval_request(
                                &approve_request.request_json,
                            ) {
                                Ok(body) => body,
                                Err(err) => {
                                    status.set(crate::i18n::tr_args(
                                        "agent_runtime.err_invalid_request",
                                        &[("error", runtime_key_pairing_error_message(err))],
                                    ));
                                    return;
                                }
                            };
                            if body.agent_id != approve_request.agent_id {
                                status.set(runtime_key_pairing_error_message(
                                    "runtime key request targets a different agent",
                                ));
                                return;
                            }
                            let api_token = token();
                            diagnostic.set(String::new());
                            let request_key = approve_request.request_key.clone();
                            let prepared_key = request_key.clone();
                            let key_state = approve_request.key_state.clone();
                            let approval_agent_id = approve_request.agent_id.clone();
                            status.set(crate::i18n::tr("agent_runtime.approving"));
                            approving.set(true);
                            spawn(async move {
                                let result = with_authed_api(&server_url, api_token, move |api| {
                                    let body = body.clone();
                                    let key_state = key_state.clone();
                                    let controller_did = controller_did.clone();
                                    let prepared_key = prepared_key.clone();
                                    async move {
                                        let submitter = api.event_submitter()?;
                                        let cached = prepared.read().clone().filter(|(key, _)| key == &prepared_key);
                                        let pair_request = if let Some((_, request)) = cached {
                                            request
                                        } else {
                                            let description = api.describe_cached().await.context("discover pairing Station")?;
                                            let service_id = description.service_id.to_string();
                                            let service_did =
                                                description.service_resolution.did.to_string();
                                            let authorization =
                                                build_agent_key_authorization_for_pairing(
                                                    &submitter,
                                                    &controller_did,
                                                    &service_id,
                                                    &key_state,
                                                    &body,
                                                )
                                                .await.context("author Agent runtime authorization")?;
                                            let authorize_event =
                                                authorization.authorize_event;
                                            let requested_scope_disclosure =
                                                build_requested_scope_disclosure_for_pairing(
                                                    &controller_did,
                                                    &service_did,
                                                    &key_state,
                                                    &body,
                                                )?;
                                            let authorize_submission = submitter
                                                .prepare_initial_submissions(std::slice::from_ref(
                                                    &authorize_event,
                                                ))
                                                .await.context("prepare Agent runtime authorization submission")?
                                                .into_iter()
                                                .next()
                                                .ok_or_else(|| {
                                                    anyhow::anyhow!(
                                                        "agent authorize submission was not prepared"
                                                    )
                                                })?;
                                            let pair_request = into_agent_key_pair_request(
                                                body,
                                                requested_scope_disclosure,
                                                authorize_submission,
                                            );
                                            prepared.set(Some((prepared_key, pair_request.clone())));
                                            pair_request
                                        };
                                        let mut outcome = submitter.agent_key_pair(&pair_request).await.context("submit Agent runtime approval")?;
                                        for _ in 0..30 {
                                            if matches!(outcome.activation_state, arkret_sdk::AgentKeyPairActivationState::Active) {
                                                break;
                                            }
                                            crate::runtime_helpers::sleep_for(Duration::from_secs(1)).await;
                                            outcome = submitter.agent_key_pair(&pair_request).await.context("await Agent runtime activation")?;
                                        }
                                        if !matches!(
                                            outcome.activation_state,
                                            arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active
                                        ) {
                                            anyhow::bail!("agent authorization is not yet active");
                                        }
                                        if outcome.authorize_event_ref
                                            != pair_request.authorize_event.event.event_id
                                        {
                                            anyhow::bail!(
                                                "agent key pairing returned a commit for a different authorization Event"
                                            );
                                        }
                                        let committed = submitter
                                            .http()
                                            .committed_event_get(&outcome.authorize_event_ref)
                                            .await?;
                                        committed.validate_shape()?;
                                        if committed.commit().event_ref != outcome.authorize_event_ref
                                            || committed.reducer_input()
                                                != Some(&pair_request.authorize_event.event)
                                        {
                                            anyhow::bail!(
                                                "agent key pairing authorization commit could not be verified"
                                            );
                                        }
                                        Ok::<_, anyhow::Error>(outcome)
                                    }
                                })
                                .await;
                                approving.set(false);
                                match result {
                                    Ok(outcome) => {
                                        handled.write().insert(request_key);
                                        pending.set(None);
                                        let next = owned_agents_rev.peek().saturating_add(1);
                                        owned_agents_rev.set(next);
                                        status.set(crate::i18n::tr_args(
                                            "agent_runtime.approved_current",
                                            &[(
                                                "id",
                                                short_protocol_id(
                                                    outcome.authorize_event_ref.as_str(),
                                                ),
                                            )],
                                        ));
                                    }
                                    Err(err) => {
                                        diagnostic.set(err.display_diagnostic());
                                        tracing::warn!(
                                            error = %err.display_diagnostic(),
                                            agent_id = %approval_agent_id,
                                            "agent runtime approval failed"
                                        );
                                        status.set(crate::i18n::tr_args(
                                            "agent_runtime.err_approval_failed",
                                            &[(
                                                "error",
                                                runtime_key_pairing_error_message(err.display_diagnostic()),
                                            )],
                                        ));
                                    }
                                }
                            });
                        },
                        if busy {
                            {crate::i18n::tr("agent_runtime.approving_button")}
                        } else {
                            {crate::i18n::tr("agent_runtime.approve")}
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct AgentRuntimeApprovalNotification {
    notification_id: NotificationId,
    approval_request_id: OpaqueLocalId,
    agent_id: DidCoreId,
}

fn agent_runtime_approval_notification(
    value: &crate::state::StoredNotification,
) -> Option<AgentRuntimeApprovalNotification> {
    let (notification_identity, data) = value.agent_runtime_approval()?;
    let arkret_sdk::NotificationIdentity::AgentApproval(notification_id) = notification_identity
    else {
        return None;
    };
    let agent_id = value.agent_runtime_approval_agent_id()?;
    Some(AgentRuntimeApprovalNotification {
        notification_id: notification_id.clone(),
        approval_request_id: data.id.clone(),
        agent_id: agent_id.clone(),
    })
}

async fn fetch_agent_runtime_approval(
    base_url: &str,
    token: String,
    notification: AgentRuntimeApprovalNotification,
) -> Result<Option<PendingAgentRuntimeApproval>, crate::transport::auth::ApiCallError> {
    with_authed_sdk_client(base_url, token, move |http| async move {
        let view = http.agent_get(notification.agent_id.as_str()).await?;
        let Some(mut request) = pending_runtime_approval_from_view(&view) else {
            return Ok(None);
        };
        if request.request_key != notification.approval_request_id {
            return Ok(None);
        }
        request.notification_id = Some(notification.notification_id);
        Ok(Some(request))
    })
    .await
}

async fn fetch_pending_agent_runtime_approval(
    base_url: &str,
    token: String,
    handled: HashSet<OpaqueLocalId>,
) -> Result<Option<PendingAgentRuntimeApproval>, crate::transport::auth::ApiCallError> {
    with_authed_sdk_client(base_url, token, move |http| async move {
        let list = http.agent_list().await?;
        for row in list.agents {
            let agent_id = row.agent_id.as_str();
            if agent_id.trim().is_empty() {
                continue;
            }
            let view = http.agent_get(agent_id).await?;
            let Some(request) = pending_runtime_approval_from_view(&view) else {
                continue;
            };
            if handled.contains(&request.request_key) {
                continue;
            }
            return Ok(Some(request));
        }
        Ok(None)
    })
    .await
}

fn pending_runtime_approval_from_view(
    view: &arkret_sdk::AgentView,
) -> Option<PendingAgentRuntimeApproval> {
    // Only a terminal (deactivated) agent has no pending approval to surface;
    // a pending runtime-key request only exists while a pairing handle is open
    // (key-management.md §3.6.1).
    if matches!(
        view.agent.lifecycle,
        arkret_sdk::AgentLifecycleState::Deactivated
    ) {
        return None;
    }
    let key_state = view.key_state.as_ref()?;
    let request_value = key_state.pending_runtime_key_request.clone()?;
    let request_json = serde_json::to_string(&request_value).ok()?;
    let summary = summarize_runtime_key_approval_request(&request_json).ok()?;
    let pairing_expires_at =
        arkret_sdk::canonical::format_timestamp_canonical(key_state.pairing_expires_at?);
    if timestamp_has_expired(&pairing_expires_at) {
        return None;
    }
    let agent_id = view.agent.agent_id.clone();
    if agent_id != summary.agent_id {
        return None;
    }
    let pairing_code = key_state.pairing_code.clone()?;
    if pairing_code.len() != 8 || !pairing_code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let request_key = key_state.approval_request_id.clone()?;
    if request_key != summary.approval_request_id {
        return None;
    }
    Some(PendingAgentRuntimeApproval {
        notification_id: None,
        request_key,
        agent_id,
        display_name: view.agent.display_name.clone().unwrap_or_default(),
        agent_slug: view.agent.slug.clone(),
        pairing_code,
        pairing_expires_at,
        verification_method: summary.verification_method,
        public_key_fingerprint: summary.public_key_fingerprint,
        key_state: key_state.clone(),
        request_json,
        // A replacement pairing is one where the agent already holds an active
        // key — projected as runtime_state replacing (key-management.md §3.6.1).
        replacement: matches!(
            crate::views::agents::model::key_state_runtime_state(key_state),
            arkret_sdk::AgentRuntimeState::Replacing
        ),
    })
}

fn approval_has_expired(request: &PendingAgentRuntimeApproval) -> bool {
    timestamp_has_expired(&request.pairing_expires_at)
}

fn timestamp_has_expired(value: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc) <= chrono::Utc::now())
        .unwrap_or(true)
}

fn approval_fallback_delay(failed: bool) -> Duration {
    let jitter = crate::clock::now_unix_ms() % 6;
    if failed {
        APPROVAL_FALLBACK_MAX_INTERVAL.saturating_sub(Duration::from_secs(jitter))
    } else {
        APPROVAL_FALLBACK_POLL_INTERVAL.saturating_add(Duration::from_secs(jitter))
    }
}

fn approval_fallback_allowed(description: Option<&arkret_sdk::ServiceDescribe>) -> bool {
    description.is_some_and(|description| {
        !description
            .supported_features
            .iter()
            .any(|feature| feature == "ak.feature.agent_runtime_approval_notifications.v1")
    })
}

fn fallback_poll_environment_ready() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .map(|window| {
                window.navigator().on_line()
                    && window.document().is_none_or(|document| !document.hidden())
            })
            .unwrap_or(true)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_summary_preserves_unknown_permissions_and_review_requirements() {
        let mut scope = crate::views::agents::requested_scope_for_presets(
            &[
                crate::views::agents::AgentGrantPreset::Read,
                crate::views::agents::AgentGrantPreset::ActOnBehalf,
            ],
            &crate::views::agents::AgentServiceScopePreset::DEFAULTS,
        )
        .unwrap();
        scope.actions.push("ak.future.permission".to_owned());
        let labels = approval_scope_summary(&scope);
        assert_eq!(
            labels
                .iter()
                .filter(|label| **label == crate::i18n::tr("agent_runtime.permission_sync"))
                .count(),
            1
        );
        assert!(
            labels
                .iter()
                .any(|label| label.contains("ak.future.permission"))
        );
        assert!(labels.contains(&crate::i18n::tr("agent_runtime.permission_review")));
    }

    #[test]
    fn approval_list_fallback_requires_a_resolved_service_without_notifications() {
        assert!(!approval_fallback_allowed(None));
        let mut description =
            crate::transport::websocket::tests_support::describe_without_websocket();
        description.supported_features.clear();
        assert!(approval_fallback_allowed(Some(&description)));
        description
            .supported_features
            .push("ak.feature.agent_runtime_approval_notifications.v1".to_owned());
        assert!(!approval_fallback_allowed(Some(&description)));
    }
}
