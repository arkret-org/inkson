use std::rc::Rc;

use glory::Scope;
use serde_json::{Value, json};

use super::model::{
    ActionApproveDialogState, ActionRequestNonceStatus, actor_kind_badge_class, actor_kind_label,
    approval_publication, build_action_approve_payload, build_action_reject_payload,
};
use crate::presentation::{InksonContext, View};
use crate::transport::auth::{ApiCallError, with_authed_api};
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;
fn approval_submit_failure(error: &ApiCallError) -> (ActionApproveDialogState, String) {
    let inner = error.inner();
    if crate::api_error::is_agent_confirmation_expired_error(inner) {
        (
            ActionApproveDialogState::Expired,
            crate::api_error::localized_error_copy("error.agent.approval_expired"),
        )
    } else if crate::api_error::is_agent_approval_required_error(inner) {
        (
            ActionApproveDialogState::Reviewing,
            crate::api_error::localized_error_copy("error.agent.approval_required"),
        )
    } else {
        (
            ActionApproveDialogState::Reviewing,
            format!("approve failed: {}", error.display()),
        )
    }
}
#[derive(Clone)]
pub struct ActionApproveDialogProps {
    pub actor_id: String,
    pub request_id: String,
    pub agent_id: String,
    pub proposed_action: String,
    pub target_json: String,
    pub publication_event: arkret_sdk::Event,
    pub expires_at: String,
    pub nonce_status: String,
}
pub fn actor_kind_badge(actor_kind: Option<String>) -> View {
    let kind = actor_kind.as_deref();
    paragraph(
        actor_kind_badge_class(kind),
        actor_kind_label(kind).unwrap_or("actor"),
    )
}
pub fn action_approve_dialog(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: ActionApproveDialogProps,
) -> View {
    let state = scope.cage(ActionApproveDialogState::Reviewing);
    let feedback = scope.cage(String::new());
    let nonce = match props.nonce_status.as_str() {
        "fresh" => ActionRequestNonceStatus::Fresh,
        "consumed" => ActionRequestNonceStatus::Consumed,
        _ => ActionRequestNonceStatus::Unknown,
    };
    let can_submit = scope.bond(move || {
        nonce != ActionRequestNonceStatus::Consumed
            && state.get() == ActionApproveDialogState::Reviewing
    });
    let owner = scope.downgrade();
    let approve_context = context.clone();
    let approval = props.clone();
    card(
        scope,
        context.clone(),
        "Approve agent action",
        vec![
            paragraph(nonce.badge_class(), format!("nonce {}", nonce.label())),
            paragraph(
                "muted",
                format!("publication Event: {}", props.publication_event.event_id),
            ),
            paragraph("muted", format!("expires_at: {}", props.expires_at)),
            line(
                "actions",
                vec![
                    action(
                        scope,
                        context.clone(),
                        "action-approve-confirm-button",
                        "Approve",
                        "primary",
                        can_submit,
                        move || {
                            if nonce == ActionRequestNonceStatus::Consumed
                                || state.get_untracked() != ActionApproveDialogState::Reviewing
                            {
                                return;
                            }
                            let context = approve_context.clone();
                            let props = approval.clone();
                            let Some(scope) = owner.upgrade() else { return };
                            let base = context.base_url.get();
                            let token = context.token.get();
                            state.revise(|value| *value = ActionApproveDialogState::Submitting);
                            spawn(&scope, async move {
                                let target =
                                    match serde_json::from_str::<arkret_sdk::AgentActionTarget>(
                                        &props.target_json,
                                    ) {
                                        Ok(target) => target,
                                        Err(error) => {
                                            state.revise(|value| {
                                                *value = ActionApproveDialogState::Reviewing
                                            });
                                            feedback.revise(|value| {
                                                *value = format!("invalid approval target: {error}")
                                            });
                                            return;
                                        }
                                    };
                                let request = json!({"request_id":props.request_id,"agent_id":props.agent_id,"proposed_action":props.proposed_action,
      "target":target,"publication_event":props.publication_event});
                                let op = build_action_approve_payload(&request, &props.expires_at)
                                    .and_then(|payload| {
                                        let publication = approval_publication(&request)?;
                                        crate::operation::TypedOperationBuilder::new::<
                                            arkret_sdk::event_spec::AgentActionApprove,
                                        >(
                                            &publication.realm_id.to_string(),
                                            &props.actor_id,
                                            payload,
                                        )
                                        .build_sdk_event("inkson")?
                                        .with_publication_event(publication)
                                    });
                                let op = match op {
                                    Ok(op) => op,
                                    Err(error) => {
                                        state.revise(|value| {
                                            *value = ActionApproveDialogState::Reviewing
                                        });
                                        feedback.revise(|value| {
                                            *value = format!("approval build failed: {error}")
                                        });
                                        return;
                                    }
                                };
                                let result = with_authed_api(&base, token, move |api| async move {
                                    api.event_submitter()?.submit_sdk_event(&op).await
                                })
                                .await;
                                match result {
                                    Ok(response) => {
                                        state.revise(|value| {
                                            *value = ActionApproveDialogState::Submitted
                                        });
                                        feedback.revise(|value| {
                                            *value =
                                                format!("approved; event_id {}", response.event_id)
                                        });
                                    }
                                    Err(error) => {
                                        let (next, message) = approval_submit_failure(&error);
                                        state.revise(|value| *value = next);
                                        feedback.revise(|value| *value = message);
                                    }
                                }
                            });
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "action-approve-reject-button",
                        "Reject",
                        "secondary",
                        scope.bond(move || state.get() != ActionApproveDialogState::Submitting),
                        move || {
                            state.revise(|value| *value = ActionApproveDialogState::Rejected);
                            feedback.revise(|value| {
                                *value =
                                    "rejected locally — no approve event will be submitted".into()
                            });
                        },
                    ),
                ],
            ),
            status(feedback),
        ],
    )
}
pub fn draft_approval_panel(
    scope: &Scope,
    context: Rc<InksonContext>,
    controller_principal_id: String,
) -> View {
    let drafts = scope.cage(Vec::<Value>::new());
    let input_value = scope.cage(String::new());
    let reason = scope.cage(String::new());
    let feedback = scope.cage(String::new());
    let list_context = context.clone();
    let list_owner = scope.downgrade();
    // A draft carries no accepted principal-control Realm binding.
    let principal_realm: Option<String> = None;
    let rows = reactive(drafts, move |scope, rows| {
        let context = list_context.clone();
        let mut children = Vec::new();
        for (index, draft) in rows.into_iter().enumerate() {
            let string = |key| {
                draft
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()
            };
            let request = string("request_id");
            let draft_id = string("draft_id");
            let id = if request.is_empty() {
                draft_id
            } else {
                request
            };
            let proposed = string("proposed_action");
            let agent = string("agent_id");
            let expires = string("expires_at");
            let body = draft
                .get("content")
                .and_then(|content| content.get("body"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let owner = list_owner.clone();
            let submit_context = context.clone();
            let actor = controller_principal_id.clone();
            let reject_context = context.clone();
            let reject_owner = list_owner.clone();
            let reject_actor = controller_principal_id.clone();
            let reject_draft = draft.clone();
            let reject_realm = principal_realm.clone();
            let can_reject = reject_realm.is_some();
            children.push(stack(
                "event agent-draft-row",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(short_protocol_id(&id)),
                            paragraph("badge", proposed),
                            paragraph("mono", short_protocol_id(&agent)),
                        ],
                    ),
                    paragraph("muted", body),
                    paragraph("muted", format!("expires_at: {expires}")),
                    line(
                        "actions",
                        vec![
                            action(
                                scope,
                                context.clone(),
                                "agent-draft-approve-button",
                                "Approve",
                                "primary",
                                true,
                                move || {
                                    let Some(scope) = owner.upgrade() else { return };
                                    let base = submit_context.base_url.get();
                                    let token = submit_context.token.get();
                                    let actor = actor.clone();
                                    let draft = draft.clone();
                                    let op = build_action_approve_payload(
                                        &draft,
                                        &crate::clock::timestamp_in(60),
                                    )
                                    .and_then(|payload| {
                                        let publication = approval_publication(&draft)?;
                                        crate::operation::TypedOperationBuilder::new::<
                                            arkret_sdk::event_spec::AgentActionApprove,
                                        >(
                                            &publication.realm_id.to_string(), &actor, payload
                                        )
                                        .build_sdk_event("inkson")?
                                        .with_publication_event(publication)
                                    });
                                    spawn(&scope, async move {
                                        let op = match op {
                                            Ok(op) => op,
                                            Err(error) => {
                                                feedback.revise(|value| {
                                                    *value =
                                                        format!("approve build failed: {error}")
                                                });
                                                return;
                                            }
                                        };
                                        let result =
                                            with_authed_api(&base, token, move |api| async move {
                                                api.event_submitter()?.submit_sdk_event(&op).await
                                            })
                                            .await;
                                        match result {
                                            Ok(response) => {
                                                drafts.revise(|rows| {
                                                    if index < rows.len() {
                                                        rows.remove(index);
                                                    }
                                                });
                                                feedback.revise(|value| {
                                                    *value = format!(
                                                        "approved; event_id {}",
                                                        response.event_id
                                                    )
                                                });
                                            }
                                            Err(error) => feedback.revise(|value| {
                                                *value = approval_submit_failure(&error).1
                                            }),
                                        }
                                    });
                                },
                            ),
                            action(
                                scope,
                                context.clone(),
                                "agent-draft-reject-button",
                                "Reject",
                                "secondary",
                                can_reject,
                                move || {
                                    let Some(realm) = reject_realm.clone() else {
                                        return;
                                    };
                                    let Some(scope) = reject_owner.upgrade() else {
                                        return;
                                    };
                                    let context = reject_context.clone();
                                    let generation = context.session_generation.get();
                                    let account = context.active_account.get();
                                    let base = context.base_url.get();
                                    let token = context.token.get();
                                    let op = build_action_reject_payload(
                                        &reject_draft,
                                        &crate::clock::now_timestamp(),
                                        Some(&reason.get()),
                                    )
                                    .and_then(|payload| {
                                        crate::operation::TypedOperationBuilder::new::<
                                            arkret_sdk::event_spec::AgentActionReject,
                                        >(
                                            &realm, &reject_actor, payload
                                        )
                                        .build_sdk_event("inkson")
                                    });
                                    let submitted = reject_draft.clone();
                                    spawn(&scope, async move {
                                        let op = match op {
                                            Ok(op) => op,
                                            Err(error) => {
                                                feedback.revise(|value| {
                                                    *value = format!("reject build failed: {error}")
                                                });
                                                return;
                                            }
                                        };
                                        let result =
                                            with_authed_api(&base, token, move |api| async move {
                                                api.event_submitter()?.submit_sdk_event(&op).await
                                            })
                                            .await;
                                        if !context.session_matches(generation, &account) {
                                            return;
                                        }
                                        match result {
                                            Ok(response) => {
                                                drafts.revise(|rows| {
                                                    if let Some(at) = rows
                                                        .iter()
                                                        .position(|row| row == &submitted)
                                                    {
                                                        rows.remove(at);
                                                    }
                                                });
                                                reason.revise(String::clear);
                                                feedback.revise(|value| {
                                                    *value = format!(
                                                        "rejected; event_id {}",
                                                        response.event_id
                                                    )
                                                });
                                            }
                                            Err(error) => feedback.revise(|value| {
                                                *value =
                                                    format!("reject failed: {}", error.display())
                                            }),
                                        }
                                    });
                                },
                            ),
                        ],
                    ),
                ],
            ));
        }
        if children.is_empty() {
            children.push(paragraph(
                "muted",
                "No drafts or action requests to review.",
            ));
        }
        stack("timeline agent-draft-list", children)
    });
    card(
        scope,
        context.clone(),
        "Draft and action approvals",
        vec![
            paragraph(
                "muted",
                "Review agent-proposed drafts or action requests before anything reaches a shared Realm. Approve submits ak.agent.action_approve; reject submits ak.agent.action_reject with a human reason when provided.",
            ),
            paragraph(
                "muted",
                "Data source: controller-owned account-data over ak.self.account.subscribe; paste a ak.agent.draft.v1 or ak.agent.action_request payload below to review it now.",
            ),
            paragraph(
                "badge amber",
                "controller principal realm unavailable — sign in to enable approvals",
            ),
            input(
                scope,
                context.clone(),
                "agent-draft-input",
                "ak.agent.draft.v1 or ak.agent.action_request payload (JSON)",
                input_value,
                true,
            ),
            input(
                scope,
                context.clone(),
                "agent-draft-reject-reason-input",
                "Optional rejection reason",
                reason,
                true,
            ),
            action(
                scope,
                context.clone(),
                "agent-draft-add-button",
                "Add approval item",
                "secondary",
                scope.bond(move || !input_value.get().trim().is_empty()),
                move || match serde_json::from_str::<Value>(&input_value.get()) {
                    Ok(value) => {
                        drafts.revise(|rows| rows.push(value));
                        input_value.revise(|value| value.clear());
                        feedback.revise(|value| *value = "approval item added".into());
                    }
                    Err(error) => feedback.revise(|value| {
                        *value = format!("approval item is not valid JSON: {error}")
                    }),
                },
            ),
            status(feedback),
            rows,
        ],
    )
}
