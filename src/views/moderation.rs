//! Moderation reviewer workbench (P3 — daily-governance UI).
//!
//! Spec: `governance/content-moderation.md` (§5 appeal lifecycle, §5.5.1.1
//! verdict enum). The appellant-facing entrypoint lives in
//! [`crate::views::moderation_appeal`]; THIS panel is the reviewer surface the
//! `moderation_appeal` module's doc-comment defers ("The full reviewer surface
//! … lives in realm_admin once wired"). It is mounted as the RealmAdmin
//! `Moderation` section and drives the already-ready P3 API:
//!
//!   * [`crate::transport::TransportClient::moderation_decide`] — seal a new decision.
//!   * [`crate::transport::TransportClient::moderation_lift`] — lift a standing decision.
//!   * [`crate::transport::TransportClient::appeal_review`] — take an appeal under review.
//!   * [`crate::transport::TransportClient::appeal_decide`] — `uphold` (no side events).
//!   * [`crate::transport::TransportClient::appeal_overturn_atomic`] — `overturn` + matching lift
//!     in one batch (§5.5.1.1 atomicity MUST).
//!   * [`crate::transport::TransportClient::appeal_modify_atomic`] — `modify` + replacement
//!     decision in one batch (§5.5.1.1 atomicity MUST).
//!   * [`crate::transport::TransportClient::appeal_close`] — terminal close.
//!
//! The work queues (standing decisions + open appeals) are projected from the
//! local raw-operation log, exactly like [`crate::views::applets`] does for the
//! applet registry — soland's projection feed fans out the same wire kinds.

use dioxus::prelude::*;
use serde_json::Value;

use crate::transport::auth::with_event_submitter;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

/// `governance/content-moderation.md` §5.5.1.1 — the closed `verdict` enum for
/// `ak.moderation.appeal.decision`. Authoritative set, drives both the UI
/// dropdown and the per-verdict submit path. Any other value is a
/// `schema_violation` server-side, so the workbench never offers one.
pub const APPEAL_VERDICTS: &[&str] = &["uphold", "overturn", "modify"];

/// The closed `decision` enum for `ak.moderation.decision`
/// (`event-payload.schema.json#/$defs/moderation_decision_payload`). Any
/// other value is a `schema_violation` server-side, so the workbench only
/// ever offers this authoritative set (the earlier `deny` / `allow` values
/// were not in the schema enum and would have been rejected).
pub const DECISION_VERDICTS: &[&str] = &["hard_deny", "soft_deny", "quarantine", "require_review"];

/// A standing moderation decision projected from the raw-operation log. Lifted
/// decisions are folded out by [`project_moderation_queues`]. The cell subject
/// is `target_ref`; `decision_ref` is the sealed decision Event's `ak:event:`
/// id (the reference a lift resolves).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingDecision {
    pub target_ref: String,
    pub decision_ref: String,
    pub decision: String,
    pub reason_code: String,
}

/// An appeal in a non-terminal state (`submitted` / `under_review`) projected
/// from the raw-operation log. `closed` and `decided` appeals drop out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenAppeal {
    pub appeal_id: String,
    pub decision_ref: String,
    pub target_ref: String,
    /// `"submitted"` or `"under_review"` — drives whether the reviewer sees a
    /// "Take review" affordance.
    pub state: String,
}

fn body_str(payload: &Value, key: &str) -> Option<String> {
    payload
        .get("body")
        .and_then(|b| b.get(key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// Read a top-level (envelope) string field — e.g. the synced `event_id`
/// that identifies a sealed decision Event.
fn top_str(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn payload_kind(payload: &Value) -> Option<&str> {
    payload.get("kind").and_then(Value::as_str)
}

/// Fold the moderation-related raw operations into the two reviewer work
/// queues. Pure (no Dioxus / IO) so the lifecycle folding is unit-tested.
///
/// Folding rules (latest-wins by log order, which is receive order):
///   * `ak.moderation.decision` adds a standing decision; `ak.moderation.decision.lift` removes the
///     one it targets.
///   * `ak.moderation.appeal.submit` opens an appeal (`submitted`); `…appeal.review` moves it to
///     `under_review`; `…appeal.decision` and `…appeal.close` are terminal and remove it from the
///     open queue.
pub fn project_moderation_queues(raw_ops: &[Value]) -> (Vec<StandingDecision>, Vec<OpenAppeal>) {
    use std::collections::BTreeMap;
    let mut decisions: BTreeMap<String, StandingDecision> = BTreeMap::new();
    let mut appeals: BTreeMap<String, OpenAppeal> = BTreeMap::new();

    for payload in raw_ops {
        match payload_kind(payload) {
            Some("ak.moderation.decision") => {
                // Cell subject is the moderated `target_ref`; the decision is
                // referenced by its sealed Event id (top-level `event_id` once
                // synced). Latest-wins by target_ref.
                if let Some(target_ref) = body_str(payload, "target_ref") {
                    decisions.insert(
                        target_ref.clone(),
                        StandingDecision {
                            target_ref,
                            decision_ref: top_str(payload, "event_id").unwrap_or_default(),
                            decision: body_str(payload, "decision").unwrap_or_default(),
                            reason_code: body_str(payload, "reason_code").unwrap_or_default(),
                        },
                    );
                }
            }
            Some("ak.moderation.decision.lift") => {
                // The lift names the moderated `target_ref` (same cell subject),
                // so drop the standing decision keyed by it.
                if let Some(target_ref) = body_str(payload, "target_ref") {
                    decisions.remove(&target_ref);
                }
            }
            Some("ak.moderation.appeal.submit") => {
                if let Some(appeal_id) = body_str(payload, "appeal_id") {
                    appeals.insert(
                        appeal_id.clone(),
                        OpenAppeal {
                            appeal_id,
                            decision_ref: body_str(payload, "decision_ref").unwrap_or_default(),
                            target_ref: body_str(payload, "target_ref").unwrap_or_default(),
                            state: "submitted".to_owned(),
                        },
                    );
                }
            }
            Some("ak.moderation.appeal.review") => {
                if let Some(appeal_id) = body_str(payload, "appeal_id")
                    && let Some(appeal) = appeals.get_mut(&appeal_id)
                {
                    appeal.state = "under_review".to_owned();
                }
            }
            Some("ak.moderation.appeal.decision") | Some("ak.moderation.appeal.close") => {
                if let Some(appeal_id) = body_str(payload, "appeal_id") {
                    appeals.remove(&appeal_id);
                }
            }
            _ => {}
        }
    }

    (
        decisions.into_values().collect(),
        appeals.into_values().collect(),
    )
}

#[component]
pub fn ModerationWorkbench(
    account_did: String,
    token: Signal<String>,
    selected_realm_id: String,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    // New-decision form state.
    let mut decide_target = use_signal(String::new);
    let mut decide_verdict = use_signal(|| "quarantine".to_owned());
    let mut decide_reason = use_signal(|| "policy_violation".to_owned());
    let mut status = use_signal(String::new);

    // Project the two work queues from the local raw-operation log.
    let raw_payloads: Vec<Value> = state_store
        .read()
        .load()
        .raw_operations
        .iter()
        .map(|r| r.payload.clone())
        .collect();
    let (standing_decisions, open_appeals) = project_moderation_queues(&raw_payloads);

    rsx! {
        div {
            class: "timeline",
            "data-testid": "moderation-workbench",
            role: "region",
            "aria-label": "Moderation reviewer workbench",

            // ── New decision ────────────────────────────────────────
            div { class: "event", "data-testid": "moderation-decide-form",
                div { class: "event-head",
                    span { "Seal moderation decision" }
                    span { class: "badge", title: "ak.moderation.decision", "Decision" }
                }
                div { class: "muted",
                    "content-moderation.md §4 — a sealed decision over a target_ref. hard_deny / soft_deny / quarantine / require_review change cross-peer visibility."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "moderation-decide-target",
                        value: "{decide_target}",
                        placeholder: "target_ref (ak:event:… / ak:strand:…)",
                        oninput: move |event: FormEvent| decide_target.set(event.value()),
                    }
                    select {
                        "data-testid": "moderation-decide-verdict",
                        value: "{decide_verdict}",
                        onchange: move |event: FormEvent| decide_verdict.set(event.value()),
                        for v in DECISION_VERDICTS.iter() {
                            option { value: "{v}", "{v}" }
                        }
                    }
                    Input {
                        "data-testid": "moderation-decide-reason",
                        value: "{decide_reason}",
                        placeholder: "reason_code",
                        oninput: move |event: FormEvent| decide_reason.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "moderation-decide-submit",
                            onclick: {
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
                                let actor = account_did.clone();
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let actor = actor.clone();
                                    let target = decide_target().trim().to_owned();
                                    let verdict = decide_verdict();
                                    let reason = decide_reason().trim().to_owned();
                                    if target.is_empty() || reason.is_empty() {
                                        status.set("target_ref + reason_code are required".to_owned());
                                        return;
                                    }
                                    let api_token = token();
                                    spawn(async move {
                                        match with_event_submitter(&base, api_token, |sub| async move {
                                            crate::transport::realm_write::moderation_decide(
                                                &sub, &realm, &actor, &target, &verdict, &reason,
                                            )
                                            .await
                                        })
                                        .await
                                        {
                                            Ok(resp) => status.set(format!(
                                                "decision sealed; event_id {}", resp.event_id
                                            )),
                                            Err(err) => status.set(format!(
                                                "decision failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Seal decision"
                        }
                    }
                    if !status().is_empty() {
                        div { class: "muted", "data-testid": "moderation-decide-status", "{status}" }
                    }
                }
            }

            // ── Standing decisions (with lift) ──────────────────────
            div { class: "event", "data-testid": "moderation-decision-queue",
                div { class: "event-head",
                    span { "Standing decisions" }
                    span { class: "badge", "{standing_decisions.len()}" }
                }
                if standing_decisions.is_empty() {
                    div { class: "muted", "data-testid": "moderation-decision-empty",
                        "No standing moderation decisions observed locally."
                    }
                } else {
                    for decision in standing_decisions.iter().cloned() {
                        {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let decision_ref_label = short_protocol_id(&decision.decision_ref);
                            let target_label = short_protocol_id(&decision.target_ref);
                            let decision_ref = decision.decision_ref.clone();
                            let target_ref = decision.target_ref.clone();
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "moderation-decision-row",
                                    "data-decision-ref": "{decision.decision_ref}",
                                    "data-target-ref": "{decision.target_ref}",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{decision.decision_ref}", "{decision_ref_label}" }
                                        span { class: "badge", "{decision.decision}" }
                                    }
                                    div { class: "muted", title: "{decision.target_ref}",
                                        "target {target_label} — {decision.reason_code}"
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "moderation-lift-button",
                                            onclick: move |_| {
                                                let base = base.clone();
                                                let realm = realm.clone();
                                                let actor = actor.clone();
                                                let decision_ref = decision_ref.clone();
                                                let target_ref = target_ref.clone();
                                                let api_token = token();
                                                spawn(async move {
                                                    match with_event_submitter(&base, api_token, |sub| async move {
                                                        crate::transport::realm_write::moderation_lift(
                                                            &sub, &realm, &actor, &target_ref, &decision_ref, "reviewer_lift",
                                                        )
                                                        .await
                                                    })
                                                    .await
                                                    {
                                                        Ok(resp) => status.set(format!(
                                                            "decision lifted; event_id {}", resp.event_id
                                                        )),
                                                        Err(err) => status.set(format!(
                                                            "lift failed: {}", err.display()
                                                        )),
                                                    }
                                                });
                                            },
                                            "Lift decision"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Open appeals (review / decide / close) ──────────────
            div { class: "event", "data-testid": "moderation-appeal-queue",
                div { class: "event-head",
                    span { "Open appeals" }
                    span { class: "badge", "{open_appeals.len()}" }
                }
                div { class: "muted",
                    "content-moderation.md §5.5.1.1 — uphold keeps the decision; overturn lifts it (atomic batch); modify replaces it (atomic batch)."
                }
                if open_appeals.is_empty() {
                    div { class: "muted", "data-testid": "moderation-appeal-empty",
                        "No open appeals."
                    }
                } else {
                    for appeal in open_appeals.iter().cloned() {
                        AppealReviewRow {
                            key: "{appeal.appeal_id}",
                            account_did: account_did.clone(),
                            token,
                            selected_realm_id: selected_realm_id.clone(),
                            appeal: appeal.clone(),
                            status,
                        }
                    }
                }
            }
        }
    }
}

/// One open-appeal row: take-review, then a verdict picker that fans out to the
/// correct (possibly atomic-batch) submit path per §5.5.1.1.
#[component]
fn AppealReviewRow(
    account_did: String,
    token: Signal<String>,
    selected_realm_id: String,
    appeal: OpenAppeal,
    status: Signal<String>,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut verdict = use_signal(|| "uphold".to_owned());
    let mut reason = use_signal(String::new);
    let mut status = status;

    let appeal_id_label = short_protocol_id(&appeal.appeal_id);
    let decision_label = short_protocol_id(&appeal.decision_ref);
    let is_submitted = appeal.state == "submitted";

    rsx! {
        div {
            class: "event",
            "data-testid": "moderation-appeal-row",
            "data-appeal-id": "{appeal.appeal_id}",
            "data-appeal-state": "{appeal.state}",
            div { class: "event-head",
                span { class: "mono", title: "{appeal.appeal_id}", "{appeal_id_label}" }
                span { class: "badge", "{appeal.state}" }
            }
            div { class: "muted", title: "{appeal.decision_ref}",
                "appeals decision {decision_label}"
            }

            if is_submitted {
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "moderation-appeal-review-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let appeal_id = appeal.appeal_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let appeal_id = appeal_id.clone();
                                let api_token = token();
                                spawn(async move {
                                    match with_event_submitter(&base, api_token, |sub| async move {
                                        crate::transport::realm_write::appeal_review(&sub, &realm, &actor, &appeal_id, None).await
                                    })
                                    .await
                                    {
                                        Ok(resp) => status.set(format!(
                                            "appeal under review; event_id {}", resp.event_id
                                        )),
                                        Err(err) => status.set(format!(
                                            "review failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Take review"
                    }
                }
            }

            div { class: "workflow-form",
                select {
                    "data-testid": "moderation-appeal-verdict",
                    value: "{verdict}",
                    onchange: move |event: FormEvent| verdict.set(event.value()),
                    for v in APPEAL_VERDICTS.iter() {
                        option { value: "{v}", "{v}" }
                    }
                }
                Textarea {
                    "data-testid": "moderation-appeal-reason",
                    value: "{reason}",
                    placeholder: "reviewer reason (required)",
                    oninput: move |event: FormEvent| reason.set(event.value()),
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "moderation-appeal-decide-button",
                        disabled: reason.read().trim().is_empty(),
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let appeal_id = appeal.appeal_id.clone();
                            let decision_ref = appeal.decision_ref.clone();
                            let target_ref = appeal.target_ref.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let appeal_id = appeal_id.clone();
                                let decision_ref = decision_ref.clone();
                                let target_ref = target_ref.clone();
                                let chosen = verdict();
                                let reason_text = format!("inline:{}", reason.read().trim());
                                let api_token = token();
                                spawn(async move {
                                    let result = match chosen.as_str() {
                                        // §5.5.1.1 overturn — appeal-decision +
                                        // matching lift MUST ride one batch.
                                        "overturn" => with_event_submitter(&base, api_token, |sub| async move {
                                            crate::transport::realm_write::appeal_overturn_atomic(
                                                &sub, &realm, &actor, &appeal_id, &target_ref, &decision_ref,
                                                &reason_text, "appeal_overturn",
                                            )
                                            .await
                                            .map(|_| "appeal overturned (decision lifted) in one batch".to_owned())
                                        })
                                        .await,
                                        // §5.5.1.1 modify — appeal-decision +
                                        // replacement decision MUST ride one batch.
                                        "modify" => with_event_submitter(&base, api_token, |sub| async move {
                                            crate::transport::realm_write::appeal_modify_atomic(
                                                &sub, &realm, &actor, &appeal_id, &target_ref,
                                                &decision_ref, "require_review", "appeal_modify", &reason_text,
                                            )
                                            .await
                                            .map(|(new_id, _)| format!(
                                                "appeal modified; new decision {}", short_protocol_id(&new_id)
                                            ))
                                        })
                                        .await,
                                        // uphold — no side events.
                                        _ => with_event_submitter(&base, api_token, |sub| async move {
                                            crate::transport::realm_write::appeal_decide(
                                                &sub, &realm, &actor, &appeal_id, "uphold", &reason_text, None,
                                            )
                                            .await
                                            .map(|resp| format!("appeal upheld; event_id {}", resp.event_id))
                                        })
                                        .await,
                                    };
                                    match result {
                                        Ok(msg) => status.set(msg),
                                        Err(err) => status.set(format!(
                                            "appeal decision failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Decide appeal"
                    }
                    Button {
                        variant: ButtonVariant::Destructive,
                        "data-testid": "moderation-appeal-close-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let appeal_id = appeal.appeal_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let appeal_id = appeal_id.clone();
                                let api_token = token();
                                spawn(async move {
                                    match with_event_submitter(&base, api_token, |sub| async move {
                                        crate::transport::realm_write::appeal_close(
                                            &sub, &realm, &actor, &appeal_id, Some("reviewer_close"),
                                        )
                                        .await
                                    })
                                    .await
                                    {
                                        Ok(resp) => status.set(format!(
                                            "appeal closed; event_id {}", resp.event_id
                                        )),
                                        Err(err) => status.set(format!(
                                            "close failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Close appeal"
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn decision_op(event_id: &str, target: &str, decision: &str) -> Value {
        json!({
            "kind": "ak.moderation.decision",
            "event_id": event_id,
            "body": {
                "target_ref": target,
                "decision": decision,
                "reason_code": "policy_violation",
            }
        })
    }

    #[test]
    fn lift_removes_the_standing_decision_it_targets() {
        let ops = vec![
            decision_op("ak:event:1", "ak:event:a", "quarantine"),
            decision_op("ak:event:2", "ak:event:b", "hard_deny"),
            json!({
                "kind": "ak.moderation.decision.lift",
                "body": { "target_ref": "ak:event:a", "decision_ref": "ak:event:1" }
            }),
        ];
        let (decisions, _) = project_moderation_queues(&ops);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].target_ref, "ak:event:b");
        assert_eq!(decisions[0].decision_ref, "ak:event:2");
        assert_eq!(decisions[0].decision, "hard_deny");
    }

    #[test]
    fn decision_verdicts_are_the_schema_closed_enum() {
        // Guard against UI drift re-adding a value the reducer would reject
        // with schema_violation (the `deny` / `allow` values are not in the
        // moderation_decision_payload `decision` enum).
        assert_eq!(
            DECISION_VERDICTS,
            &["hard_deny", "soft_deny", "quarantine", "require_review"]
        );
    }

    #[test]
    fn appeal_lifecycle_folds_submitted_then_under_review_then_terminal() {
        // submit → review keeps it open as under_review.
        let open = vec![
            json!({
                "kind": "ak.moderation.appeal.submit",
                "body": {
                    "appeal_id": "ak:appeal:1",
                    "decision_ref": "ak:decision:1",
                    "target_ref": "ak:event:a",
                }
            }),
            json!({
                "kind": "ak.moderation.appeal.review",
                "body": { "appeal_id": "ak:appeal:1" }
            }),
        ];
        let (_, appeals) = project_moderation_queues(&open);
        assert_eq!(appeals.len(), 1);
        assert_eq!(appeals[0].state, "under_review");
        assert_eq!(appeals[0].decision_ref, "ak:decision:1");

        // A terminal decision/close removes it from the open queue.
        for terminal in [
            "ak.moderation.appeal.decision",
            "ak.moderation.appeal.close",
        ] {
            let mut ops = open.clone();
            ops.push(json!({ "kind": terminal, "body": { "appeal_id": "ak:appeal:1" } }));
            let (_, appeals) = project_moderation_queues(&ops);
            assert!(
                appeals.is_empty(),
                "{terminal} must remove the appeal from the open queue"
            );
        }
    }

    #[test]
    fn appeal_verdict_enum_matches_spec_closed_set() {
        // §5.5.1.1 closed enum — guard against UI drift adding a value the
        // reducer would reject with schema_violation.
        assert_eq!(APPEAL_VERDICTS, &["uphold", "overturn", "modify"]);
    }
}
