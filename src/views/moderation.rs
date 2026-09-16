//! Moderation decision workbench.
//!
//! The product exposes only `ak.moderation.decision` and
//! `ak.moderation.decision.lift` as signed, convergent governance primitives.

use arkret_wire::event_kind_str;
use dioxus::prelude::*;
use serde_json::Value;

use crate::i18n::{tr, tr_args};
use crate::transport::auth::with_event_submitter;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::views::helpers::short_protocol_id;

pub const DECISION_VERDICTS: &[&str] = &["hard_deny", "soft_deny", "quarantine", "require_review"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingDecision {
    pub target_ref: String,
    pub decision_ref: String,
    pub decision: String,
    pub reason_code: String,
}

fn body_str(payload: &Value, key: &str) -> Option<String> {
    payload
        .get("body")
        .and_then(|body| body.get(key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

pub fn project_moderation_decisions(raw_ops: &[Value]) -> Vec<StandingDecision> {
    use std::collections::BTreeMap;

    let mut decisions = BTreeMap::<String, StandingDecision>::new();
    for payload in raw_ops {
        match payload.get("kind").and_then(Value::as_str) {
            Some(event_kind_str::MODERATION_DECISION) => {
                if let Some(target_ref) = body_str(payload, "target_ref") {
                    decisions.insert(
                        target_ref.clone(),
                        StandingDecision {
                            target_ref,
                            decision_ref: payload
                                .get("event_id")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                            decision: body_str(payload, "decision").unwrap_or_default(),
                            reason_code: body_str(payload, "reason_code").unwrap_or_default(),
                        },
                    );
                }
            }
            Some(event_kind_str::MODERATION_DECISION_LIFT) => {
                if let Some(target_ref) = body_str(payload, "target_ref") {
                    decisions.remove(&target_ref);
                }
            }
            _ => {}
        }
    }
    decisions.into_values().collect()
}

#[component]
pub fn ModerationWorkbench(
    principal_id: String,
    token: Signal<String>,
    selected_realm_id: String,
) -> Element {
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let mut target = use_signal(String::new);
    let mut verdict = use_signal(|| "quarantine".to_owned());
    let mut reason = use_signal(|| "policy_violation".to_owned());
    let mut status = use_signal(String::new);
    let operations = state_store
        .read()
        .load()
        .raw_operations
        .iter()
        .map(|record| record.payload.clone())
        .collect::<Vec<_>>();
    let standing = project_moderation_decisions(&operations);

    rsx! {
        div {
            class: "timeline",
            "data-testid": "moderation-workbench",
            role: "region",
            "aria-label": tr("moderation.workbench_aria_label"),
            div { class: "event", "data-testid": "moderation-decide-form",
                div { class: "event-head",
                    span { {tr("moderation.decide_title")} }
                    span { class: "badge", title: event_kind_str::MODERATION_DECISION, {tr("moderation.decide_badge")} }
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "moderation-decide-target",
                        value: "{target}",
                        placeholder: tr("moderation.target_placeholder"),
                        oninput: move |event: FormEvent| target.set(event.value()),
                    }
                    select {
                        "data-testid": "moderation-decide-verdict",
                        value: "{verdict}",
                        onchange: move |event: FormEvent| verdict.set(event.value()),
                        for value in DECISION_VERDICTS.iter() {
                            option { value: "{value}", "{value}" }
                        }
                    }
                    Input {
                        "data-testid": "moderation-decide-reason",
                        value: "{reason}",
                        placeholder: "reason_code",
                        oninput: move |event: FormEvent| reason.set(event.value()),
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "moderation-decide-submit",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = principal_id.clone();
                            move |_| {
                                let target_ref = target().trim().to_owned();
                                let decision = verdict();
                                let reason_code = reason().trim().to_owned();
                                if target_ref.is_empty() || reason_code.is_empty() {
                                    status.set("target_ref + reason_code are required".to_owned());
                                    return;
                                }
                                let (base, realm, actor) = (base.clone(), realm.clone(), actor.clone());
                                let api_token = token();
                                spawn(async move {
                                    match with_event_submitter(&base, api_token, |submitter| async move {
                                        crate::transport::realm_write::moderation_decide(
                                            &submitter, &realm, &actor, &target_ref, &decision, &reason_code,
                                        )
                                        .await
                                    })
                                    .await
                                    {
                                        Ok(response) => status.set(format!("decision sealed; event_id {}", response.event_id)),
                                        Err(error) => status.set(format!("decision failed: {}", error.display())),
                                    }
                                });
                            }
                        },
                        {tr("moderation.decide_submit")}
                    }
                }
            }
            div { class: "event", "data-testid": "moderation-decision-queue",
                div { class: "event-head",
                    span { {tr("moderation.standing_title")} }
                    span { class: "badge", "{standing.len()}" }
                }
                if standing.is_empty() {
                    div { class: "muted", {tr("moderation.standing_empty")} }
                } else {
                    for decision in standing.iter().cloned() {
                        {
                            let (base, realm, actor) = (base_url.clone(), selected_realm_id.clone(), principal_id.clone());
                            let decision_ref = decision.decision_ref.clone();
                            let target_ref = decision.target_ref.clone();
                            let decision_label = short_protocol_id(&decision_ref);
                            let target_label = short_protocol_id(&target_ref);
                            rsx! {
                                div { class: "event", "data-testid": "moderation-decision-row",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{decision.decision_ref}", "{decision_label}" }
                                        span { class: "badge", "{decision.decision}" }
                                    }
                                    div { class: "muted", title: "{decision.target_ref}",
                                        {tr_args(
                                            "moderation.decision_row_summary",
                                            &[
                                                ("target", target_label.clone()),
                                                ("reason", decision.reason_code.clone()),
                                            ],
                                        )}
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "moderation-lift-button",
                                        onclick: move |_| {
                                            let (base, realm, actor) = (base.clone(), realm.clone(), actor.clone());
                                            let (decision_ref, target_ref) = (decision_ref.clone(), target_ref.clone());
                                            let api_token = token();
                                            spawn(async move {
                                                match with_event_submitter(&base, api_token, |submitter| async move {
                                                    crate::transport::realm_write::moderation_lift(
                                                        &submitter, &realm, &actor, &target_ref, &decision_ref, "reviewer_lift",
                                                    )
                                                    .await
                                                })
                                                .await
                                                {
                                                    Ok(response) => status.set(format!("decision lifted; event_id {}", response.event_id)),
                                                    Err(error) => status.set(format!("lift failed: {}", error.display())),
                                                }
                                            });
                                        },
                                        {tr("moderation.lift")}
                                    }
                                }
                            }
                        }
                    }
                }
                if !status().is_empty() {
                    div { class: "muted", "data-testid": "moderation-status", "{status}" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn lift_removes_the_standing_decision_it_targets() {
        let operations = vec![
            json!({
                "kind": "ak.moderation.decision",
                "event_id": "ak:event:A42FkwFdQPw7aC_yPcdlVU5ZjKLAnFCbmrXTVRJTNhRc",
                "body": { "target_ref": "target", "decision": "quarantine", "reason_code": "policy_violation" }
            }),
            json!({
                "kind": "ak.moderation.decision.lift",
                "body": { "target_ref": "target" }
            }),
        ];
        assert!(project_moderation_decisions(&operations).is_empty());
    }

    #[test]
    fn decision_verdicts_are_closed() {
        assert_eq!(
            DECISION_VERDICTS,
            &["hard_deny", "soft_deny", "quarantine", "require_review"]
        );
    }
}
