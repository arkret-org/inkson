use std::collections::HashSet;
use std::time::Duration;

use dioxus::prelude::*;
use serde_json::Value;

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::views::agents::{
    build_agent_key_authorize_event_for_pairing, parse_runtime_key_approval_request,
    runtime_key_pairing_error_message, summarize_runtime_key_approval_request,
};
use crate::views::helpers::{short_protocol_id, with_authed_api};

const APPROVAL_POLL_INTERVAL: Duration = Duration::from_millis(5_000);

#[derive(Clone, Debug, PartialEq)]
struct PendingAgentRuntimeApproval {
    request_key: String,
    agent_principal_id: String,
    display_name: String,
    agent_slug: String,
    pairing_code: String,
    approval_requested_at: String,
    proof_expires_at: String,
    verification_method: String,
    public_key_fingerprint: String,
    key_state: Value,
    request_json: String,
}

#[component]
pub fn AgentRuntimeApprovalPrompt(
    base_url: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
) -> Element {
    let mut pending = use_signal(|| None::<PendingAgentRuntimeApproval>);
    let mut handled = use_signal(HashSet::<String>::new);
    let mut status = use_signal(String::new);
    let mut approving = use_signal(|| false);

    {
        let base_url = base_url;
        let token = token;
        use_future(move || async move {
            loop {
                let has_prompt = pending.read().is_some();
                if has_prompt {
                    crate::api::sleep_for(APPROVAL_POLL_INTERVAL).await;
                    continue;
                }

                let api_token = token();
                if api_token.trim().is_empty() {
                    crate::api::sleep_for(APPROVAL_POLL_INTERVAL).await;
                    continue;
                }

                let base = base_url();
                let handled_keys = handled.read().clone();
                match fetch_pending_agent_runtime_approval(&base, api_token, handled_keys).await {
                    Ok(Some(request)) => {
                        status.set(String::new());
                        pending.set(Some(request));
                    }
                    Ok(None) => {
                        status.set(String::new());
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err.display(),
                            "agent runtime approval polling failed"
                        );
                    }
                }

                crate::api::sleep_for(APPROVAL_POLL_INTERVAL).await;
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
        short_protocol_id(&request.agent_principal_id)
    } else {
        request.display_name.clone()
    };
    let agent_id_label = short_protocol_id(&request.agent_principal_id);
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
                    div {
                        class: "device-pair-approval-device",
                        "data-testid": "agent-runtime-approval-agent",
                        "data-agent-id": "{request.agent_principal_id}",
                        strong { "{agent_label}" }
                        span { class: "muted mono", "{agent_id_label}" }
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
                            if body.agent_principal_id.as_str()
                                != approve_request.agent_principal_id
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
                                        let service_did =
                                            api.describe_cached().await?.service_did.to_string();
                                        let authorize_event =
                                            build_agent_key_authorize_event_for_pairing(
                                                &controller,
                                                &service_did,
                                                &key_state,
                                                &body,
                                            )?;
                                        api.agent_key_pair_with_authorize_event(
                                            body,
                                            &authorize_event,
                                        )
                                        .await
                                    }
                                })
                                .await;
                                approving.set(false);
                                match result {
                                    Ok(outcome) => {
                                        handled.write().insert(request_key);
                                        pending.set(None);
                                        status.set(format!(
                                            "Runtime key approved: {}.",
                                            short_protocol_id(
                                                outcome.authorized_event_ref.as_str(),
                                            )
                                        ));
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

async fn fetch_pending_agent_runtime_approval(
    base_url: &str,
    token: String,
    handled: HashSet<String>,
) -> Result<Option<PendingAgentRuntimeApproval>, crate::api::ApiCallError> {
    with_authed_api(base_url, token, move |api| async move {
        let list = api.agent_list().await?;
        for row in list.agents {
            if row.get("status").and_then(Value::as_str) != Some("pending_runtime_key") {
                continue;
            }
            let Some(agent_principal_id) = row
                .get("agent_principal_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            else {
                continue;
            };
            let view = api.agent_get(agent_principal_id).await?;
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
    view: &cokret_sdk::AgentView,
) -> Option<PendingAgentRuntimeApproval> {
    if view.status != "pending_runtime_key" {
        return None;
    }
    let request_value = view.key_state.get("pending_runtime_key_request")?.clone();
    if request_value.is_null() {
        return None;
    }
    let request_json = serde_json::to_string(&request_value).ok()?;
    let summary = summarize_runtime_key_approval_request(&request_json).ok()?;
    let agent_principal_id = agent_field(view, "agent_principal_id")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| summary.agent_principal_id.clone());
    if agent_principal_id != summary.agent_principal_id {
        return None;
    }
    let pairing_code = key_state_str(&view.key_state, "pairing_code")?;
    let request_key = key_state_str(&view.key_state, "approval_request_id")
        .or_else(|| Some(summary.pairing_request_id.clone()))?;
    Some(PendingAgentRuntimeApproval {
        request_key,
        agent_principal_id,
        display_name: agent_field(view, "display_name").unwrap_or_default(),
        agent_slug: agent_field(view, "agent_slug").unwrap_or_default(),
        pairing_code,
        approval_requested_at: key_state_str(&view.key_state, "approval_requested_at")
            .unwrap_or_default(),
        proof_expires_at: summary.proof_expires_at,
        verification_method: summary.verification_method,
        public_key_fingerprint: summary.public_key_fingerprint,
        key_state: view.key_state.clone(),
        request_json,
    })
}

fn agent_field(view: &cokret_sdk::AgentView, key: &str) -> Option<String> {
    view.agent
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn key_state_str(key_state: &Value, key: &str) -> Option<String> {
    key_state
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}
