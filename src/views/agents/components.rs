//! Reusable agent UI components: actor-kind badge, the action-approve dialog, and the
//! controller-owned draft-approval panel.

use dioxus::prelude::*;
use serde_json::{Value, json};

use super::model::{
    ActionApproveDialogState, ActionRequestNonceStatus, actor_kind_badge_class, actor_kind_label,
    build_action_approve_payload, build_action_reject_payload, is_action_request_expired,
};
use crate::transport::auth::with_authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::views::helpers::short_protocol_id;

/// Render the non-authoritative `actor_kind` badge from an Actor Profile. Pure helper so
/// the dashboard / chat / kanban can reuse the same colored chip
/// without duplicating the mapping.
#[component]
pub fn ActorKindBadge(actor_kind: Option<String>) -> Element {
    let kind = actor_kind.as_deref();
    let label = actor_kind_label(kind).unwrap_or("actor");
    let class = actor_kind_badge_class(kind);
    rsx! {
        span {
            class: "{class}",
            "data-testid": "actor-kind-badge",
            "data-actor-kind": kind.unwrap_or("unknown"),
            "{label}"
        }
    }
}

/// Action-approve dialog component. Renders the payload digest,
/// expiry, and single-use nonce status of an incoming
/// `ak.agent.action_request` notification; on confirm it submits a
/// `ak.agent.action_approve` event.
///
/// TODO(P3-impl): the action_request payload pipe goes through
/// chime's push frame parser (chime P3) → this dialog. Today the
/// dialog accepts a payload-digest string as input so the wire
/// envelope can be exercised; full integration with the notification
/// stream lands in P3-impl.
#[component]
pub fn ActionApproveDialog(
    token: Signal<String>,
    actor_id: String,
    space_id: String,
    request_id: String,
    agent_id: String,
    proposed_action: String,
    target_json: String,
    payload_digest: String,
    expires_at: String,
    nonce_status: String,
    now: String,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state = use_signal(|| ActionApproveDialogState::Reviewing);
    let mut status_text = use_signal(String::new);

    let expired = is_action_request_expired(&expires_at, &now);
    let nonce_st = match nonce_status.as_str() {
        "fresh" => ActionRequestNonceStatus::Fresh,
        "consumed" => ActionRequestNonceStatus::Consumed,
        _ => ActionRequestNonceStatus::Unknown,
    };
    let can_submit = !expired
        && nonce_st != ActionRequestNonceStatus::Consumed
        && state() == ActionApproveDialogState::Reviewing;

    rsx! {
        div {
            class: "event",
            "data-testid": "action-approve-dialog",
            "data-state": "{state().as_data_state()}",
            "data-request-id": "{request_id}",
            div { class: "event-head",
                span { "Approve agent action" }
                span { class: "{nonce_st.badge_class()}", "nonce {nonce_st.label()}" }
            }
            div { class: "muted", "data-testid": "action-approve-payload-digest",
                "payload digest: {payload_digest}"
            }
            div { class: "muted", "data-testid": "action-approve-expires-at",
                "expires_at: {expires_at}"
            }
            if expired {
                div {
                    class: "badge red",
                    "data-testid": "action-approve-expiry-blocked",
                    "expired — submit rejected"
                }
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "action-approve-confirm-button",
                    disabled: !can_submit,
                    onclick: {
                        let base = base_url.clone();
                        let actor = actor_id.clone();
                        let space = space_id.clone();
                        let request_id = request_id.clone();
                        let agent = agent_id.clone();
                        let action = proposed_action.clone();
                        let target_json = target_json.clone();
                        let digest = payload_digest.clone();
                        let approval_expires_at = expires_at.clone();
                        move |_| {
                            state.set(ActionApproveDialogState::Submitting);
                            let base = base.clone();
                            let actor = actor.clone();
                            let space = space.clone();
                            let request_id = request_id.clone();
                            let agent = agent.clone();
                            let action = action.clone();
                            let target_json = target_json.clone();
                            let digest = digest.clone();
                            let approval_expires_at = approval_expires_at.clone();
                            let api_token = token();
                            spawn(async move {
                                // Submit a ak.agent.action_approve
                                // event. The payload carries the
                                // request_id + the digest we approved
                                // so the reducer can match it back to
                                // the originating action_request and
                                // burn the single-use nonce.
                                let target = serde_json::from_str::<Value>(&target_json)
                                    .unwrap_or_else(|_| json!({
                                        "kind": "realm",
                                        "realm_id": space.clone(),
                                    }));
                                let request_payload = json!({
                                    "request_id": request_id,
                                    "agent_id": agent,
                                    "proposed_action": action,
                                    "target": target,
                                    "request_canonical_digest": digest,
                                });
                                let approved_at = crate::clock::now_timestamp();
                                let op = build_action_approve_payload(
                                    &request_payload,
                                    &approved_at,
                                    &approval_expires_at,
                                )
                                .and_then(|payload| {
                                    crate::operation::TypedOperationBuilder::new::<
                                        arkret_sdk::event_spec::AgentActionApprove,
                                    >(
                                        &space,
                                        &actor,
                                        payload,
                                    )
                                    .build_sdk_event("inkson")
                                });
                                let op = match op {
                                    Ok(op) => op,
                                    Err(err) => {
                                        state.set(ActionApproveDialogState::Reviewing);
                                        status_text.set(format!("approval build failed: {err}"));
                                        return;
                                    }
                                };
                                match with_authed_api(&base, api_token, move |api| {
                                    let op = op.clone();
                                    async move {
                                        api.event_submitter()?.submit_sdk_event(&op).await
                                    }
                                })
                                .await
                                {
                                    Ok(resp) => {
                                        state.set(ActionApproveDialogState::Submitted);
                                        status_text.set(format!(
                                            "approved; event_id {}",
                                            resp.event_id
                                        ));
                                    }
                                    Err(err) => {
                                        state.set(ActionApproveDialogState::Reviewing);
                                        status_text.set(format!(
                                            "approve failed: {}", err.display()
                                        ));
                                    }
                                }
                            });
                        }
                    },
                    "Approve"
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "action-approve-reject-button",
                    disabled: state() == ActionApproveDialogState::Submitting,
                    onclick: move |_| {
                        state.set(ActionApproveDialogState::Rejected);
                        status_text.set("rejected locally — no approve event will be submitted".to_owned());
                    },
                    "Reject"
                }
            }
            if !status_text().is_empty() {
                div { class: "muted", "data-testid": "action-approve-status", "{status_text}" }
            }
        }
    }
}

/// Approval panel for controller-owne`ak.agent.action_approve
/// requests. Lets `ak.agent.action_rejectwith `ak.agent.action_approve`
/// or reject with `ak.agent.action_reject`.
///
/// `ak.self.accounttroller-owned account-data over
/// `ak.self.account.subscribe`; until the subscribe fold is attached to
/// this component, operators can paste a draft or action request payload.
#[component]
pub fn DraftApprovalPanel(token: Signal<String>, controller_principal_id: String) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut drafts = use_signal(Vec::<Value>::new);
    let mut draft_input = use_signal(String::new);
    let mut panel_status = use_signal(String::new);
    let mut reject_reason = use_signal(String::new);

    // Controller-private events (action_approve / action_reject) author
    // in the controller's principal-control realm.
    // The draft DTO does not carry the controller's accepted PCR create or a
    // typed PCR binding. Keep approval disabled instead of deriving a Realm
    // identifier from the controller DID.
    let principal_realm: Option<String> = None;

    rsx! {
        div { class: "event", "data-testid": "agent-draft-approval",
            div { class: "event-head",
                span { "Draft and action approvals" }
                span { class: "badge blue", "ak.agent.* approval" }
            }
            div { class: "muted",
                "Review agent-proposed drafts or action requests before anything reaches a shared Realm. Approve submits ak.agent.action_approve; reject submits ak.agent.action_reject with a human reason when provided."
            }
            div { class: "muted", "data-testid": "agent-draft-data-source",
                "Data source: controller-owned account-data over ak.self.account.subscribe; paste a ak.agent.draft.v1 or ak.agent.action_request payload below to review it now."
            }
            if principal_realm.is_none() {
                div { class: "badge amber", "data-testid": "agent-draft-no-realm",
                    "controller principal realm unavailable — sign in to enable approvals"
                }
            }
            div { class: "workflow-form",
                Input {
                    "data-testid": "agent-draft-input",
                    placeholder: "ak.agent.draft.v1 or ak.agent.action_request payload (JSON)",
                    value: "{draft_input}",
                    oninput: move |event: FormEvent| draft_input.set(event.value()),
                }
                Input {
                    "data-testid": "agent-draft-reject-reason-input",
                    placeholder: "Optional rejection reason",
                    value: "{reject_reason}",
                    oninput: move |event: FormEvent| reject_reason.set(event.value()),
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-draft-add-button",
                        disabled: draft_input().trim().is_empty(),
                        onclick: move |_| {
                            match serde_json::from_str::<Value>(draft_input().as_str()) {
                                Ok(value) => {
                                    drafts.write().push(value);
                                    draft_input.set(String::new());
                                    panel_status.set("approval item added".to_owned());
                                }
                                Err(err) => panel_status.set(format!(
                                    "approval item is not valid JSON: {err}"
                                )),
                            }
                        },
                        "Add approval item"
                    }
                }
                if !panel_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-draft-status", "{panel_status}" }
                }
            }
            if drafts.read().is_empty() {
                div { class: "muted", "data-testid": "agent-draft-empty",
                    "No drafts or action requests to review."
                }
            } else {
                div { class: "timeline", "data-testid": "agent-draft-list",
                    for (idx, draft) in drafts.read().iter().enumerate() {
                        {
                            let request_id = draft
                                .get("request_id")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let draft_id = draft
                                .get("draft_id")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let item_id = if request_id.is_empty() {
                                draft_id.clone()
                            } else {
                                request_id.clone()
                            };
                            let item_id = if item_id.is_empty() {
                                "?".to_owned()
                            } else {
                                item_id
                            };
                            let proposed_action = draft
                                .get("proposed_action")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let agent_id = draft
                                .get("agent_id")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let expires_at = draft
                                .get("expires_at")
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let body_preview = draft
                                .get("content")
                                .and_then(|c| c.get("body"))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let agent_id_label = short_protocol_id(&agent_id);
                            let item_id_label = short_protocol_id(&item_id);
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "agent-draft-row",
                                    "data-draft-id": "{draft_id}",
                                    "data-request-id": "{request_id}",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{item_id}", "{item_id_label}" }
                                        span { class: "badge", "{proposed_action}" }
                                        span { class: "mono", title: "{agent_id}", "agent {agent_id_label}" }
                                    }
                                    if !body_preview.is_empty() {
                                        div { class: "muted", "draft: {body_preview}" }
                                    }
                                    div { class: "muted", "expires_at: {expires_at}" }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Primary,
                                            "data-testid": "agent-draft-approve-button",
                                            disabled: principal_realm.is_none(),
                                            onclick: {
                                                let base = base_url.clone();
                                                let actor = controller_principal_id.clone();
                                                let realm = principal_realm.clone();
                                                move |_| {
                                                    let Some(realm) = realm.clone() else { return; };
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let draft = drafts.read()[idx].clone();
                                                    // Default approval window: 1h
                                                    // from now, single-use nonce.
                                                    let approved_at = crate::clock::now_timestamp();
                                                    let approval_expires_at = crate::clock::timestamp_in(60);
                                                    let op = build_action_approve_payload(
                                                        &draft,
                                                        &approved_at,
                                                        &approval_expires_at,
                                                    )
                                                    .and_then(|payload| {
                                                        crate::operation::TypedOperationBuilder::new::<
                                                            arkret_sdk::event_spec::AgentActionApprove,
                                                        >(
                                                            &realm,
                                                            &actor,
                                                            payload,
                                                        )
                                                        .build_sdk_event("inkson")
                                                    });
                                                    spawn(async move {
                                                        let op = match op {
                                                            Ok(op) => op,
                                                            Err(err) => {
                                                                panel_status.set(format!(
                                                                    "approve build failed: {err}"
                                                                ));
                                                                return;
                                                            }
                                                        };
                                                        match with_authed_api(&base, api_token, move |api| {
                                                            let op = op.clone();
                                                            async move {
                                                                api.event_submitter()?.submit_sdk_event(&op).await
                                                            }
                                                        })
                                                        .await
                                                        {
                                                            Ok(resp) => {
                                                                drafts.write().remove(idx);
                                                                panel_status.set(format!(
                                                                    "approved; event_id {}",
                                                                    resp.event_id
                                                                ));
                                                            }
                                                            Err(err) => panel_status.set(format!(
                                                                "approve failed: {}", err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            "Approve"
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-draft-reject-button",
                                            disabled: principal_realm.is_none(),
                                            onclick: {
                                                let base = base_url.clone();
                                                let actor = controller_principal_id.clone();
                                                let realm = principal_realm.clone();
                                                move |_| {
                                                    let Some(realm) = realm.clone() else { return; };
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let draft = drafts.read()[idx].clone();
                                                    let reason = reject_reason();
                                                    let rejected_at = crate::clock::now_timestamp();
                                                    let op = build_action_reject_payload(
                                                        &draft,
                                                        &rejected_at,
                                                        Some(&reason),
                                                    )
                                                    .and_then(|payload| {
                                                        crate::operation::TypedOperationBuilder::new::<
                                                            arkret_sdk::event_spec::AgentActionReject,
                                                        >(
                                                            &realm,
                                                            &actor,
                                                            payload,
                                                        )
                                                        .build_sdk_event("inkson")
                                                    });
                                                    spawn(async move {
                                                        let op = match op {
                                                            Ok(op) => op,
                                                            Err(err) => {
                                                                panel_status.set(format!(
                                                                    "reject build failed: {err}"
                                                                ));
                                                                return;
                                                            }
                                                        };
                                                        match with_authed_api(&base, api_token, move |api| {
                                                            let op = op.clone();
                                                            async move {
                                                                api.event_submitter()?.submit_sdk_event(&op).await
                                                            }
                                                        })
                                                        .await
                                                        {
                                                            Ok(resp) => {
                                                                drafts.write().remove(idx);
                                                                reject_reason.set(String::new());
                                                                panel_status.set(format!(
                                                                    "rejected; event_id {}",
                                                                    resp.event_id
                                                                ));
                                                            }
                                                            Err(err) => panel_status.set(format!(
                                                                "reject failed: {}", err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            "Reject"
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
