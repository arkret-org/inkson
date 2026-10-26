//! Moderation decision workbench.
//!
//! The product exposes only `ak.moderation.decision` and
//! `ak.moderation.decision.lift` as signed, convergent governance primitives.

use std::rc::Rc;

use arkret_wire::event_kind_str;
use glory::prelude::*;
use serde_json::Value;

use crate::i18n::tr_args;
use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};
use crate::transport::auth::with_event_submitter;
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

pub fn page(scope: &Scope, context: Rc<InksonContext>, route: crate::routes::Route) -> View {
    let realm = route
        .realm_id()
        .unwrap_or(&context.selected_realm_id.get())
        .to_owned();
    workbench(scope, context, realm)
}
pub fn workbench(scope: &Scope, context: Rc<InksonContext>, realm: String) -> View {
    let target = scope.cage(String::new());
    let verdict = scope.cage("quarantine".to_owned());
    let reason = scope.cage("policy_violation".to_owned());
    let status = scope.cage(String::new());
    let busy = scope.cage(false);
    let weak = scope.downgrade();
    let submit_context = context.clone();
    let submit_realm = realm.clone();
    let submit = crate::views::settings::widgets::action(
        scope,
        context.clone(),
        "moderation-submit",
        "moderation.decide_submit",
        "primary",
        scope.bond(move || !busy.get()),
        move || {
            let target = target.get().trim().to_owned();
            let verdict = verdict.get();
            let reason = reason.get().trim().to_owned();
            if target.is_empty() || reason.is_empty() {
                status.revise(|value| *value = "target_ref + reason_code are required".into());
                return;
            }
            let Some(owner) = weak.upgrade() else { return };
            let context = submit_context.clone();
            let realm = submit_realm.clone();
            let generation = context.session_generation.get();
            let account = context.active_account.get();
            busy.revise(|value| *value = true);
            let weak = owner.downgrade();
            let _ = owner.spawn(async move {
                let actor = crate::app::principal_id_owned(context.principal_id.get());
                let result = with_event_submitter(
                    &context.base_url.get(),
                    context.token.get(),
                    |submitter| async move {
                        crate::transport::realm_write::moderation_decide(
                            &submitter, &realm, &actor, &target, &verdict, &reason,
                        )
                        .await
                    },
                )
                .await;
                if weak.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                status.revise(|value| {
                    *value = match result {
                        Ok(response) => format!("decision sealed; event_id {}", response.event_id),
                        Err(error) => format!("decision failed: {}", error.display()),
                    }
                });
                busy.revise(|value| *value = false);
            });
        },
    );
    let queue = reactive(
        scope.bond({
            let context = context.clone();
            move || (context.state_revision.get(), context.locale.get())
        }),
        {
            let context = context.clone();
            move |scope, _| {
                let operations = context.state_store.read(|store| {
                    store
                        .load()
                        .raw_operations
                        .iter()
                        .map(|record| record.payload.clone())
                        .collect::<Vec<_>>()
                });
                let standing = project_moderation_decisions(&operations);
                let mut rows = vec![paragraph(
                    "event-head",
                    context.translated(scope, "moderation.standing_title"),
                )];
                for decision in standing {
                    let target = decision.target_ref.clone();
                    let reference = decision.decision_ref.clone();
                    let realm = realm.clone();
                    let context = context.clone();
                    let weak = scope.downgrade();
                    rows.push(Box::new(view().class("event").fill(vec![
                        paragraph("event-head mono", short_protocol_id(&reference)),
                        paragraph("badge", decision.decision),
                        paragraph(
                            "muted",
                            tr_args(
                                "moderation.decision_row_summary",
                                &[
                                    ("target", short_protocol_id(&target)),
                                    ("reason", decision.reason_code),
                                ],
                            ),
                        ),
                        crate::views::settings::widgets::action(
                            scope,
                            context.clone(),
                            "moderation-lift",
                            "moderation.lift",
                            "secondary",
                            scope.bond(move || !busy.get()),
                            move || {
                                let Some(owner) = weak.upgrade() else { return };
                                let target = target.clone();
                                let reference = reference.clone();
                                let realm = realm.clone();
                                let context = context.clone();
                                let generation = context.session_generation.get();
                                let account = context.active_account.get();
                                let weak = owner.downgrade();
                                busy.revise(|value| *value = true);
                                let _ = owner.spawn(async move {
                                    let actor =
                                        crate::app::principal_id_owned(context.principal_id.get());
                                    let result = with_event_submitter(
                                        &context.base_url.get(),
                                        context.token.get(),
                                        |submitter| async move {
                                            crate::transport::realm_write::moderation_lift(
                                                &submitter,
                                                &realm,
                                                &actor,
                                                &target,
                                                &reference,
                                                "reviewer_lift",
                                            )
                                            .await
                                        },
                                    )
                                    .await;
                                    if weak.upgrade().is_none()
                                        || !context.session_matches(generation, &account)
                                    {
                                        return;
                                    }
                                    status.revise(|value| {
                                        *value = match result {
                                            Ok(response) => format!(
                                                "decision lifted; event_id {}",
                                                response.event_id
                                            ),
                                            Err(error) => {
                                                format!("lift failed: {}", error.display())
                                            }
                                        }
                                    });
                                    busy.revise(|value| *value = false);
                                });
                            },
                        ),
                    ])) as View);
                }
                if rows.len() == 1 {
                    rows.push(paragraph(
                        "muted",
                        context.translated(scope, "moderation.standing_empty"),
                    ));
                }
                rows.push(paragraph("muted", status));
                Box::new(view().class("event").fill(rows)) as View
            }
        },
    );
    Box::new(view().class("timeline").fill(vec![
        Box::new(view().class("event").fill(vec![
                    paragraph(
                        "event-head",
                        context.translated(scope, "moderation.decide_title"),
                    ),
                    input_field(
                        context.clone(),
                        "moderation-target",
                        context.translated(scope, "moderation.target_placeholder"),
                        target,
                        Purpose::Text,
                    ),
                    crate::views::settings::widgets::choice(
                        scope,
                        context.clone(),
                        "moderation-verdict",
                        "moderation.decide_badge",
                        verdict,
                        DECISION_VERDICTS
                            .iter()
                            .map(|value| (value.to_string(), value.to_string()))
                            .collect(),
                        true,
                        move |next| verdict.revise(|value| *value = next),
                    ),
                    input_field(
                        context.clone(),
                        "moderation-reason",
                        "reason_code",
                        reason,
                        Purpose::Text,
                    ),
                    submit,
                ])) as View,
        queue,
    ]))
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
