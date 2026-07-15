use std::collections::HashSet;
use std::time::Duration;

use dioxus::prelude::*;
use serde_json::Value;

use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::views::agents::{
    bootstrap_provisioned_agent, build_agent_key_authorize_event_for_pairing,
    parse_runtime_key_approval_request, runtime_key_pairing_error_message,
    summarize_runtime_key_approval_request,
};
use crate::views::helpers::short_protocol_id;

const APPROVAL_FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(30);
const APPROVAL_FALLBACK_MAX_INTERVAL: Duration = Duration::from_secs(60);
const APPROVAL_NOTIFICATION_FEATURE: &str = "ak.feature.agent_runtime_approval_notifications.v1";

#[derive(Clone, Debug, PartialEq)]
struct PendingAgentRuntimeApproval {
    notification_id: String,
    request_key: String,
    agent_id: String,
    display_name: String,
    agent_slug: String,
    pairing_code: String,
    approval_requested_at: String,
    proof_expires_at: String,
    verification_method: String,
    public_key_fingerprint: String,
    key_state: Value,
    request_json: String,
    replacement: bool,
}

#[component]
pub fn AgentRuntimeApprovalPrompt(token: Signal<String>, account_did: Signal<String>) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::get().base_url;
    let mut pending = use_signal(|| None::<PendingAgentRuntimeApproval>);
    let mut handled = use_signal(HashSet::<String>::new);
    let mut status = use_signal(String::new);
    let mut approving = use_signal(|| false);
    let state_store = crate::app::SessionContext::get().state_store;

    {
        let base_url = base_url;
        let token = token;
        use_effect(move || {
            let projection = state_store.read().notification_projection();
            let open = projection
                .iter()
                .filter_map(agent_runtime_approval_notification)
                .collect::<Vec<_>>();
            if pending.read().as_ref().is_some_and(|request| {
                !open
                    .iter()
                    .any(|notification| notification.notification_id == request.notification_id)
            }) {
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
            let base = base_url();
            let api_token = token();
            if api_token.trim().is_empty() {
                return;
            }
            spawn(async move {
                match fetch_agent_runtime_approval(&base, api_token, notification).await {
                    Ok(Some(request)) => {
                        status.set(String::new());
                        pending.set(Some(request));
                    }
                    Ok(None) => {}
                    Err(error) => tracing::warn!(
                        error = %error.display(),
                        "agent runtime approval notification refresh failed"
                    ),
                }
            });
        });
    }

    {
        let base_url = base_url;
        let token = token;
        use_future(move || async move {
            loop {
                let has_prompt = pending.read().is_some();
                if has_prompt {
                    if pending.read().as_ref().is_some_and(approval_has_expired) {
                        pending.set(None);
                        approving.set(false);
                        status.set(String::new());
                    }
                    crate::runtime_helpers::sleep_for(APPROVAL_FALLBACK_POLL_INTERVAL).await;
                    continue;
                }

                if !fallback_poll_environment_ready() {
                    crate::runtime_helpers::sleep_for(APPROVAL_FALLBACK_POLL_INTERVAL).await;
                    continue;
                }

                let api_token = token();
                if api_token.trim().is_empty() {
                    crate::runtime_helpers::sleep_for(APPROVAL_FALLBACK_POLL_INTERVAL).await;
                    continue;
                }

                let base = base_url();
                match server_supports_approval_notifications(&base, api_token.clone()).await {
                    Ok(true) | Err(_) => {
                        crate::runtime_helpers::sleep_for(APPROVAL_FALLBACK_POLL_INTERVAL).await;
                        continue;
                    }
                    Ok(false) => {}
                }
                let handled_keys = handled.read().clone();
                let failed = match fetch_pending_agent_runtime_approval(
                    &base,
                    api_token,
                    handled_keys,
                )
                .await
                {
                    Ok(Some(request)) => {
                        status.set(String::new());
                        pending.set(Some(request));
                        false
                    }
                    Ok(None) => {
                        status.set(String::new());
                        false
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err.display(),
                            "agent runtime approval polling failed"
                        );
                        true
                    }
                };

                crate::runtime_helpers::sleep_for(approval_fallback_delay(failed)).await;
            }
        });
    }

    if token().trim().is_empty() {
        return rsx! {};
    }

    let Some(request) = pending() else {
        return rsx! {};
    };

    let agent_label = if request.display_name.trim().is_empty() {
        short_protocol_id(&request.agent_id)
    } else {
        request.display_name.clone()
    };
    let agent_id_label = short_protocol_id(&request.agent_id);
    let verification_label = short_protocol_id(&request.verification_method);
    let fingerprint_label = short_protocol_id(&request.public_key_fingerprint);
    let status_value = status();
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
                    approving.set(false);
                }
            },
            "data-testid": "agent-runtime-approval-modal",
            "aria-labelledby": "agent-runtime-approval-title",
            "aria-label": "An agent runtime is requesting access to your account",
            div { class: "modal event",
                div { class: "modal-head event-head",
                    h3 { id: "agent-runtime-approval-title", "Agent runtime approval requested" }
                    span { class: "muted", "agent pairing" }
                }
                div { class: "modal-body",
                    p { class: "muted",
                        "An agent runtime is asking to finish pairing. Approve only if you started this request and the code matches the runtime screen."
                    }
                    if request.replacement {
                        p { class: "warning", "This replaces a runtime key on an active or paused Agent." }
                    }
                    div {
                        class: "device-pair-approval-device",
                        "data-testid": "agent-runtime-approval-agent",
                        "data-agent-id": "{request.agent_id}",
                        strong { "{agent_label}" }
                        if agent_label != agent_id_label {
                            span { class: "muted mono", "{agent_id_label}" }
                        }
                        if !request.agent_slug.trim().is_empty() {
                            span { class: "muted", "Slug: {request.agent_slug}" }
                        }
                        if !request.approval_requested_at.trim().is_empty() {
                            span { class: "muted", "Requested {request.approval_requested_at}" }
                        }
                    }
                    div { class: "device-pair-approval-code-block",
                        span { class: "muted", "Compare this code before approving" }
                        strong {
                            class: "device-pair-approval-code mono",
                            "data-testid": "agent-runtime-approval-code",
                            "{request.pairing_code}"
                        }
                    }
                    div {
                        class: "device-pair-approval-device",
                        "data-testid": "agent-runtime-approval-runtime-key",
                        span { class: "muted", "Runtime key" }
                        strong { class: "mono", "{fingerprint_label}" }
                        span { class: "muted mono", "{verification_label}" }
                        if !request.proof_expires_at.trim().is_empty() {
                            span { class: "muted", "Proof expires {request.proof_expires_at}" }
                        }
                    }
                    if !status_value.is_empty() {
                        div { class: "muted", "data-testid": "agent-runtime-approval-status", "{status_value}" }
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
                                let base = base_url();
                                let api_token = token();
                                let agent_id = reject_agent_id.clone();
                                approving.set(true);
                                status.set("Rejecting request and rotating the pairing code...".to_owned());
                                spawn(async move {
                                    let result = with_authed_sdk_client(&base, api_token, move |http| {
                                        let agent_id = agent_id.clone();
                                        async move {
                                            http.agent_renew_pairing(
                                                &agent_id,
                                                &arkret_sdk::models::AgentRenewPairingRequestBody::default(),
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
                                            status.set("Request rejected and pairing code rotated.".to_owned());
                                        }
                                        Err(error) => status.set(format!(
                                            "Could not rotate the pairing code. {}",
                                            error.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Reject and rotate code"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-runtime-approval-dismiss",
                        disabled: busy,
                        onclick: move |_| {
                            handled.write().insert(dismiss_button_key.clone());
                            pending.set(None);
                            status.set(String::new());
                            approving.set(false);
                        },
                        "Dismiss"
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "agent-runtime-approval-approve",
                        disabled: busy,
                        onclick: move |_| {
                            if approving() {
                                return;
                            }
                            let controller = account_did();
                            if controller.trim().is_empty() {
                                status.set("Cannot approve without an active account.".to_owned());
                                return;
                            }
                            let body = match parse_runtime_key_approval_request(
                                &approve_request.request_json,
                            ) {
                                Ok(body) => body,
                                Err(err) => {
                                    status.set(format!(
                                        "Runtime key request is invalid. {}",
                                        runtime_key_pairing_error_message(err)
                                    ));
                                    return;
                                }
                            };
                            if body.agent_id.as_str()
                                != approve_request.agent_id
                            {
                                status.set(runtime_key_pairing_error_message(
                                    "runtime key request targets a different agent",
                                ));
                                return;
                            }
                            let base = base_url();
                            let api_token = token();
                            let request_key = approve_request.request_key.clone();
                            let key_state = approve_request.key_state.clone();
                            status.set("Approving agent runtime...".to_owned());
                            approving.set(true);
                            spawn(async move {
                                let result = with_authed_api(&base, api_token, move |api| {
                                    let body = body.clone();
                                    let key_state = key_state.clone();
                                    let controller = controller.clone();
                                    async move {
                                        let bootstrap_key_state: arkret_sdk::models::KeyState =
                                            serde_json::from_value(key_state.clone()).map_err(
                                                |error| {
                                                    anyhow::anyhow!(
                                                        "Agent key state is invalid: {error}"
                                                    )
                                                },
                                            )?;
                                        let previous_seal_id = match &bootstrap_key_state
                                            .pcr_recovery
                                        {
                                            arkret_sdk::models::AgentPcrRecoveryState::Ready {
                                                managed_frontier_ref,
                                                ..
                                            }
                                            | arkret_sdk::models::AgentPcrRecoveryState::Stale {
                                                managed_frontier_ref,
                                                ..
                                            } => Some(managed_frontier_ref.seal_ref.clone()),
                                            arkret_sdk::models::AgentPcrRecoveryState::Pending => {
                                                None
                                            }
                                        };
                                        let service_id =
                                            api.describe_cached().await?.service_id.to_string();
                                        let authorize_event =
                                            build_agent_key_authorize_event_for_pairing(
                                                &controller,
                                                &service_id,
                                                &key_state,
                                                &body,
                                            )?;
                                        let pair_request =
                                            body.into_pair_request(authorize_event.clone());
                                        let outcome = api
                                            .event_submitter()?
                                            .agent_key_pair_with_authorize_event(
                                                pair_request,
                                                &authorize_event,
                                            )
                                            .await?;
                                        let recovery_refresh_error = bootstrap_provisioned_agent(
                                            &api,
                                            state_store,
                                            &bootstrap_key_state.agent_id,
                                            &bootstrap_key_state.principal_control_realm_id,
                                            &bootstrap_key_state.controller_authorization_ref,
                                            previous_seal_id.as_deref(),
                                        )
                                        .await
                                        .err()
                                        .map(|error| error.to_string());
                                        Ok::<_, anyhow::Error>((outcome, recovery_refresh_error))
                                    }
                                })
                                .await;
                                approving.set(false);
                                match result {
                                    Ok((outcome, recovery_refresh_error)) => {
                                        handled.write().insert(request_key);
                                        pending.set(None);
                                        status.set(if let Some(error) = recovery_refresh_error {
                                            format!(
                                                "Runtime key approved: {}. Agent PCR recovery refresh failed: {error}",
                                                short_protocol_id(
                                                    outcome.authorized_event_ref.as_str(),
                                                )
                                            )
                                        } else {
                                            format!(
                                                "Runtime key approved: {}. Agent PCR recovery is current.",
                                                short_protocol_id(
                                                    outcome.authorized_event_ref.as_str(),
                                                )
                                            )
                                        });
                                    }
                                    Err(err) => {
                                        status.set(format!(
                                            "Runtime key approval failed. {}",
                                            runtime_key_pairing_error_message(err.display())
                                        ));
                                    }
                                }
                            });
                        },
                        if busy {
                            "Approving..."
                        } else {
                            "Approve"
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct AgentRuntimeApprovalNotification {
    notification_id: String,
    approval_request_id: String,
    agent_id: String,
}

fn agent_runtime_approval_notification(value: &Value) -> Option<AgentRuntimeApprovalNotification> {
    if value.get("type").and_then(Value::as_str) != Some("agent")
        || value.pointer("/data/kind").and_then(Value::as_str) != Some("agent_runtime_approval")
    {
        return None;
    }
    let expires_at = value.pointer("/data/expires_at")?.as_str()?.to_owned();
    if timestamp_has_expired(&expires_at) {
        return None;
    }
    Some(AgentRuntimeApprovalNotification {
        notification_id: value.get("id")?.as_str()?.to_owned(),
        approval_request_id: value
            .pointer("/data/approval_request_id")?
            .as_str()?
            .to_owned(),
        agent_id: value.pointer("/data/agent_id")?.as_str()?.to_owned(),
    })
}

async fn server_supports_approval_notifications(
    base_url: &str,
    token: String,
) -> Result<bool, crate::transport::auth::ApiCallError> {
    with_authed_api(base_url, token, |api| async move {
        let description = api.describe_cached().await?;
        Ok(description
            .supported_features
            .iter()
            .any(|feature| feature == APPROVAL_NOTIFICATION_FEATURE))
    })
    .await
}

async fn fetch_agent_runtime_approval(
    base_url: &str,
    token: String,
    notification: AgentRuntimeApprovalNotification,
) -> Result<Option<PendingAgentRuntimeApproval>, crate::transport::auth::ApiCallError> {
    with_authed_sdk_client(base_url, token, move |http| async move {
        let view = http.agent_get(&notification.agent_id).await?;
        let Some(mut request) = pending_runtime_approval_from_view(&view) else {
            return Ok(None);
        };
        if request.agent_id != notification.agent_id
            || request.request_key != notification.approval_request_id
        {
            return Ok(None);
        }
        request.notification_id = notification.notification_id;
        Ok(Some(request))
    })
    .await
}

async fn fetch_pending_agent_runtime_approval(
    base_url: &str,
    token: String,
    handled: HashSet<String>,
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
    if !matches!(
        view.status,
        arkret_sdk::AgentStatus::PendingRuntimeKey
            | arkret_sdk::AgentStatus::Active
            | arkret_sdk::AgentStatus::Paused
    ) {
        return None;
    }
    let key_state = view.key_state.as_ref()?;
    let request_value = key_state.pending_runtime_key_request.clone()?;
    if request_value.is_empty() {
        return None;
    }
    let request_json = serde_json::to_string(&request_value).ok()?;
    let summary = summarize_runtime_key_approval_request(&request_json).ok()?;
    if timestamp_has_expired(&summary.proof_expires_at)
        || key_state
            .pairing_expires_at
            .is_some_and(|expires_at| timestamp_has_expired(&expires_at.to_rfc3339()))
    {
        return None;
    }
    let agent_id = view.agent.agent_id.to_string();
    if agent_id != summary.agent_id {
        return None;
    }
    let pairing_code = key_state.pairing_code.clone()?;
    let request_key = key_state
        .approval_request_id
        .clone()
        .unwrap_or_else(|| summary.pairing_request_id.clone());
    Some(PendingAgentRuntimeApproval {
        notification_id: String::new(),
        request_key,
        agent_id,
        display_name: view.agent.display_name.clone().unwrap_or_default(),
        agent_slug: view.agent.slug.clone(),
        pairing_code,
        approval_requested_at: key_state
            .approval_requested_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_default(),
        proof_expires_at: summary.proof_expires_at,
        verification_method: summary.verification_method,
        public_key_fingerprint: summary.public_key_fingerprint,
        key_state: serde_json::to_value(key_state).ok()?,
        request_json,
        replacement: matches!(
            view.status,
            arkret_sdk::AgentStatus::Active | arkret_sdk::AgentStatus::Paused
        ),
    })
}

fn approval_has_expired(request: &PendingAgentRuntimeApproval) -> bool {
    timestamp_has_expired(&request.proof_expires_at)
}

fn timestamp_has_expired(value: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc) <= chrono::Utc::now())
        .unwrap_or(true)
}

fn approval_fallback_delay(failed: bool) -> Duration {
    if !failed {
        return APPROVAL_FALLBACK_POLL_INTERVAL;
    }
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u64 % 6)
        .unwrap_or_default();
    APPROVAL_FALLBACK_MAX_INTERVAL.saturating_sub(Duration::from_secs(jitter))
}

fn fallback_poll_environment_ready() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window()
            .map(|window| {
                window.navigator().on_line()
                    && window.document().is_none_or(|document| !document.hidden())
            })
            .unwrap_or(true);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        true
    }
}
