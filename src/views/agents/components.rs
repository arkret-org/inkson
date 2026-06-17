//! Reusable agent UI components: actor-kind badge, sidecar thread guard,
//! sidecar exposure disclosure, the action-approve dialog, and the
//! controller-owned draft-approval panel.

use dioxus::prelude::*;
use serde_json::{Value, json};

use super::model::{
    ActionApproveDialogState, ActionRequestNonceStatus, actor_kind_badge_class, actor_kind_label,
    build_action_approve_payload, build_action_reject_payload, is_action_request_expired,
};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Render an `actor_kind` badge for a single envelope. Pure helper so
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

/// Sidecar Thread guard: a sidecar thread is a `controller × native
/// agent` 1:1 channel. CKP-0008 §4.5 and CKP-0009 §3 invariant 10
/// require the renderer to refuse to expose it as a group chat. The
/// component renders the inner children only when the participant
/// list contains exactly the controller DID and one native agent
/// DID; otherwise it shows a placeholder.
#[component]
pub fn SidecarThreadGuard(
    controller_did: String,
    agent_id: String,
    participants: Vec<String>,
    children: Element,
) -> Element {
    let normalized: Vec<String> = participants
        .iter()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    let mut expected = vec![controller_did.clone(), agent_id.clone()];
    expected.sort();
    let mut found = normalized.clone();
    found.sort();
    let ok = normalized.len() == 2 && expected == found;
    rsx! {
        if ok {
            div {
                class: "event",
                "data-testid": "sidecar-thread-guard-ok",
                "data-controller-did": "{controller_did}",
                "data-agent-did": "{agent_id}",
                {children}
            }
        } else {
            div {
                class: "event",
                "data-testid": "sidecar-thread-guard-placeholder",
                div { class: "event-head",
                    span { "Sidecar thread" }
                    span { class: "badge amber", "1:1 invariant violated" }
                }
                div { class: "muted",
                    "CKP-0008 §4.5 / CKP-0009 §3 invariant 10 — sidecar threads are controller × native-agent 1:1 channels and MUST NOT render as a group chat. Refusing to render this thread until the participant set normalizes."
                }
                div { class: "muted",
                    "Expected controller: {controller_did}; agent: {agent_id}. Observed {normalized.len()} participant(s)."
                }
            }
        }
    }
}

/// CKP-0009 §3 invariant 10 / CKP-0008 §4.5 — sidecar exposure
/// disclosure panel. Before resume, the controller MUST acknowledge any
/// sidecar Circles that became newly visible while the agent was paused.
/// The acknowledged object_refs feed `resume_sidecar_refs`, which the
/// resume button folds into a real `agent_sidecar_exposure_ack`.
///
/// Data source: soland's sidecar exposure projection
/// (`ck.agent.sidecar_projection.v1`) is not yet wired, so the disclosed
/// refs are entered by the operator here; once the projection ships, the
/// agent view's exposure field populates this list automatically.
#[component]
pub fn SidecarExposureDisclosure(
    controller_did: String,
    resume_sidecar_refs: Signal<Vec<String>>,
) -> Element {
    let mut ref_input = use_signal(String::new);
    rsx! {
        div { class: "event", "data-testid": "sidecar-exposure-disclosure",
            div { class: "event-head",
                span { "Sidecar exposure disclosure" }
                span { class: "badge", "CKP-0009 §3 inv. 10" }
            }
            div { class: "muted",
                "Controller: {controller_did}. Before resuming a paused agent, acknowledge any sidecar Circles that became newly visible while it was paused. Acknowledged refs are sent as the resume sidecar_exposure_ack."
            }
            div { class: "muted", "data-testid": "sidecar-exposure-data-source",
                "Data source: soland sidecar exposure projection (ck.agent.sidecar_projection.v1) pending — enter the disclosed sidecar object_refs below until the projection auto-populates this list."
            }
            div { class: "workflow-form",
                Input {
                    "data-testid": "sidecar-exposure-ref-input",
                    placeholder: "sidecar object_ref (ck:circle:... or ck:strand:...)",
                    value: "{ref_input}",
                    oninput: move |event: FormEvent| ref_input.set(event.value()),
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "sidecar-exposure-ack-add-button",
                        disabled: ref_input().trim().is_empty(),
                        onclick: move |_| {
                            let value = ref_input().trim().to_owned();
                            if value.is_empty() { return; }
                            let mut refs = resume_sidecar_refs.write();
                            if !refs.contains(&value) {
                                refs.push(value);
                            }
                            ref_input.set(String::new());
                        },
                        "Acknowledge ref"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "sidecar-exposure-ack-clear-button",
                        disabled: resume_sidecar_refs.read().is_empty(),
                        onclick: move |_| resume_sidecar_refs.set(Vec::new()),
                        "Clear"
                    }
                }
                if resume_sidecar_refs.read().is_empty() {
                    div { class: "muted", "data-testid": "sidecar-exposure-ack-empty",
                        "No newly-exposed sidecars acknowledged. Resume will send no exposure ack."
                    }
                } else {
                    div { class: "timeline", "data-testid": "sidecar-exposure-ack-list",
                        for sidecar_ref in resume_sidecar_refs.read().iter() {
                            div {
                                class: "metric",
                                "data-testid": "sidecar-exposure-ack-row",
                                "data-sidecar-ref": "{sidecar_ref}",
                                span { class: "mono", "{sidecar_ref}" }
                                span { class: "badge green", "acknowledged" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Action-approve dialog component. Renders the payload digest,
/// expiry, and single-use nonce status of an incoming
/// `ck.agent.action_request` notification; on confirm it submits a
/// `ck.agent.action_approve` event.
///
/// TODO(P3-impl): the action_request payload pipe goes through
/// chime's push frame parser (chime P3) → this dialog. Today the
/// dialog accepts a payload-digest string as input so the wire
/// envelope can be exercised; full integration with the notification
/// stream lands in P3-impl.
#[component]
pub fn ActionApproveDialog(
    base_url: String,
    token: Signal<String>,
    actor_id: String,
    space_id: String,
    request_id: String,
    payload_digest: String,
    expires_at: String,
    nonce_status: String,
    now: String,
) -> Element {
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
                        let digest = payload_digest.clone();
                        move |_| {
                            state.set(ActionApproveDialogState::Submitting);
                            let base = base.clone();
                            let actor = actor.clone();
                            let space = space.clone();
                            let request_id = request_id.clone();
                            let digest = digest.clone();
                            let api_token = token();
                            spawn(async move {
                                // Submit a ck.agent.action_approve
                                // event. The payload carries the
                                // request_id + the digest we approved
                                // so the reducer can match it back to
                                // the originating action_request and
                                // burn the single-use nonce.
                                let op = crate::operation::OperationBuilder::new(
                                    &space,
                                    &actor,
                                    "ck.agent.action_approve",
                                )
                                .body(json!({
                                    "request_id": request_id,
                                    "payload_digest": digest,
                                }))
                                .build("yougen");
                                match with_authed_api(&base, api_token, move |api| {
                                    let op = op.clone();
                                    async move {
                                        api.submit_event_envelope(&op).await
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

/// CKP-0008 §4.8 — controller-owned draft approval panel. Lists
/// `ck.agent.draft.v1` drafts and lets the controller approve (submits
/// `ck.agent.action_approve`) or reject (submits `ck.agent.action_reject`).
///
/// Data source: drafts are delivered as controller-owned account-data
/// over `ck.self.account.subscribe`. soland's draft materialization
/// (agent `ck.agent.draft.propose` → controller `ck.agent.draft.v1`) is
/// pending, so the list is populated here by pasting a draft payload;
/// the approve / reject call chain is fully wired and exercises the real
/// wire envelope today. Once the projection ships, the subscribe fold
/// auto-populates this list.
#[component]
pub fn DraftApprovalPanel(
    base_url: String,
    token: Signal<String>,
    controller_did: String,
) -> Element {
    let mut drafts = use_signal(Vec::<Value>::new);
    let mut draft_input = use_signal(String::new);
    let mut panel_status = use_signal(String::new);

    // Controller-private events (action_approve / action_reject) author
    // in the controller's principal-control realm.
    let principal_realm = cokret_sdk::Did::new(controller_did.clone())
        .ok()
        .map(|principal| cokret_sdk::auth::principal_control_realm_id(&principal).to_string());

    rsx! {
        div { class: "event", "data-testid": "agent-draft-approval",
            div { class: "event-head",
                span { "Draft approvals" }
                span { class: "badge blue", "ck.agent.draft.v1" }
            }
            div { class: "muted",
                "Review agent-proposed drafts before anything reaches a shared Realm. Approve submits ck.agent.action_approve (binds draft_id + content digest + single-use nonce + expiry); reject submits ck.agent.action_reject."
            }
            div { class: "muted", "data-testid": "agent-draft-data-source",
                "Data source: controller-owned account-data over ck.self.account.subscribe; soland draft materialization pending — paste a ck.agent.draft.v1 payload below to review it now."
            }
            if principal_realm.is_none() {
                div { class: "badge amber", "data-testid": "agent-draft-no-realm",
                    "controller principal realm unavailable — sign in to enable approvals"
                }
            }
            div { class: "workflow-form",
                Input {
                    "data-testid": "agent-draft-input",
                    placeholder: "ck.agent.draft.v1 payload (JSON)",
                    value: "{draft_input}",
                    oninput: move |event: FormEvent| draft_input.set(event.value()),
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
                                    panel_status.set("draft added".to_owned());
                                }
                                Err(err) => panel_status.set(format!(
                                    "draft is not valid JSON: {err}"
                                )),
                            }
                        },
                        "Add draft"
                    }
                }
                if !panel_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-draft-status", "{panel_status}" }
                }
            }
            if drafts.read().is_empty() {
                div { class: "muted", "data-testid": "agent-draft-empty",
                    "No drafts to review."
                }
            } else {
                div { class: "timeline", "data-testid": "agent-draft-list",
                    for (idx, draft) in drafts.read().iter().enumerate() {
                        {
                            let draft_id = draft
                                .get("draft_id")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let proposed_action = draft
                                .get("proposed_action")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let agent_id = draft
                                .get("agent_principal_id")
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
                            let draft_id_label = short_protocol_id(&draft_id);
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "agent-draft-row",
                                    "data-draft-id": "{draft_id}",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{draft_id}", "{draft_id_label}" }
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
                                                let actor = controller_did.clone();
                                                let realm = principal_realm.clone();
                                                move |_| {
                                                    let Some(realm) = realm.clone() else { return; };
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let draft = drafts.read()[idx].clone();
                                                    // Default approval window: 1h
                                                    // from now, single-use nonce.
                                                    let approval_expires_at = crate::clock::rfc3339_secs_in(60);
                                                    let payload = build_action_approve_payload(
                                                        &draft, &approval_expires_at,
                                                    );
                                                    let op = crate::operation::OperationBuilder::new(
                                                        &realm,
                                                        &actor,
                                                        "ck.agent.action_approve",
                                                    )
                                                    .body(payload)
                                                    .build("yougen");
                                                    spawn(async move {
                                                        match with_authed_api(&base, api_token, move |api| {
                                                            let op = op.clone();
                                                            async move {
                                                                api.submit_event_envelope(&op).await
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
                                                let actor = controller_did.clone();
                                                let realm = principal_realm.clone();
                                                move |_| {
                                                    let Some(realm) = realm.clone() else { return; };
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let draft = drafts.read()[idx].clone();
                                                    let payload = build_action_reject_payload(&draft);
                                                    let op = crate::operation::OperationBuilder::new(
                                                        &realm,
                                                        &actor,
                                                        "ck.agent.action_reject",
                                                    )
                                                    .body(payload)
                                                    .build("yougen");
                                                    spawn(async move {
                                                        match with_authed_api(&base, api_token, move |api| {
                                                            let op = op.clone();
                                                            async move {
                                                                api.submit_event_envelope(&op).await
                                                            }
                                                        })
                                                        .await
                                                        {
                                                            Ok(resp) => {
                                                                drafts.write().remove(idx);
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
