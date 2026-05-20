//! Round R2/R3 (T06) — moderation appeal user flow.
//!
//! Per `governance/content-moderation.md` §4 (Round R2/R3), every
//! moderation decision the reducer emits MUST give the affected user an
//! "Appeal this decision" entrypoint. The four-event lifecycle is:
//!
//! - `cx.moderation.appeal.submit`   — user files the appeal
//! - `cx.moderation.appeal.review`   — reviewer takes the file
//! - `cx.moderation.appeal.decision` — reviewer decides
//!   (uphold / overturn / modify)
//! - `cx.moderation.appeal.close`    — appeal terminal
//!
//! This module exposes:
//!
//! 1. `AppealState` — UI-side projection of the four wire states the
//!    user sees (submitted / under_review / decided / closed).
//! 2. `AppealSubmitter` component — renders the entrypoint button near
//!    a moderation decision and submits the
//!    `cx.moderation.appeal.submit` event via the durable event channel.
//!
//! The full reviewer surface (Review/Decision/Close authoring) is admin
//! scope and lives in `space_admin.rs` once wired. See
//! `// TODO(round23-T06)` markers below for the deferred pieces.

use chrono::Utc;
use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::operation::OperationBuilder;
use crate::views::helpers::with_authed_api;

/// User-facing projection of the four moderation appeal wire states.
///
/// Wire kinds (Round R2/R3):
/// - `cx.moderation.appeal.submit`   → [`AppealState::Submitted`]
/// - `cx.moderation.appeal.review`   → [`AppealState::UnderReview`]
/// - `cx.moderation.appeal.decision` → [`AppealState::Decided { .. }`]
/// - `cx.moderation.appeal.close`    → [`AppealState::Closed`]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppealState {
    None,
    Submitted,
    UnderReview,
    Decided { verdict: String },
    Closed,
}

impl AppealState {
    pub fn from_latest_event_kind(kind: &str, payload: &Value) -> Self {
        match kind {
            "cx.moderation.appeal.submit" => Self::Submitted,
            "cx.moderation.appeal.review" => Self::UnderReview,
            "cx.moderation.appeal.decision" => {
                let verdict = payload
                    .get("verdict")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_owned();
                Self::Decided { verdict }
            }
            "cx.moderation.appeal.close" => Self::Closed,
            _ => Self::None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            AppealState::None => "moderation.appeal.state.none",
            AppealState::Submitted => "moderation.appeal.state.submitted",
            AppealState::UnderReview => "moderation.appeal.state.under_review",
            AppealState::Decided { .. } => "moderation.appeal.state.decided",
            AppealState::Closed => "moderation.appeal.state.closed",
        }
    }
}

/// Construct the canonical `cx.moderation.appeal.submit` event payload as
/// an [`OperationBuilder`]. The wire shape matches
/// [`contrix_sdk::AppealSubmitPayload`] / `cx.schema.moderation_appeal.v1`.
///
/// Inputs:
/// - `decision_event_id` — the `cx:event:` id of the original moderation
///   decision being appealed (used as `decision_ref`).
/// - `target_ref` — opaque pointer to the moderated content
///   (`cx:event:…` for a message, `cx:flow:…` for a flow, etc.).
/// - `reason_text_ref` — blob ref or inline string carrying the appeal
///   narrative (server may require a `cx:blob:…` ref for E2EE Realms).
pub fn build_appeal_submit_op(
    realm_id: &str,
    appellant: &str,
    appeal_id: &str,
    decision_event_id: &str,
    target_ref: &str,
    reason_text_ref: &str,
) -> anyhow::Result<OperationBuilder> {
    // Round R2/R3: typed appeal id binding. Validate the input rather than
    // forwarding free-form strings to the wire — the SDK's TypedAppealId
    // enforces the `cx:appeal:<uuidv7>` shape.
    let typed_appeal_id = contrix_sdk::TypedAppealId::new(appeal_id)
        .map_err(|err| anyhow::anyhow!("invalid appeal_id: {err}"))?;
    let payload = contrix_sdk::AppealSubmitPayload {
        appeal_id: typed_appeal_id.clone(),
        decision_ref: contrix_sdk::EventId::new(decision_event_id)
            .map_err(|err| anyhow::anyhow!("invalid decision_event_id: {err}"))?,
        target_ref: target_ref.to_owned(),
        appellant: contrix_sdk::Did::new(appellant)
            .map_err(|err| anyhow::anyhow!("invalid appellant did: {err}"))?,
        reason_text_ref: reason_text_ref.to_owned(),
        evidence_refs: Vec::new(),
        evidence_visibility: None,
        created_at: Utc::now(),
    };
    // Validate via the SDK's oneOf-aware checker before serialization so a
    // future evolution of the payload (Decision::Modify needs a
    // modify_decision_ref, etc.) can't slip past.
    contrix_sdk::ModerationAppealPayload::Submit(payload.clone()).validate_minimal()?;

    let body = serde_json::to_value(&payload)?;
    Ok(
        OperationBuilder::new(realm_id, appellant, "cx.moderation.appeal.submit")
            .target_ref(decision_event_id)
            .body(json!({
                "schema": contrix_sdk::ModerationAppealPayload::SCHEMA,
                "appeal_id": body["appeal_id"],
                "decision_ref": body["decision_ref"],
                "target_ref": body["target_ref"],
                "appellant": body["appellant"],
                "reason_text_ref": body["reason_text_ref"],
                "evidence_refs": body["evidence_refs"],
                "created_at": body["created_at"],
            })),
    )
}

/// Build a fresh `cx:appeal:<uuidv7>` id for a new appeal. UUIDv7 inherits
/// process clock entropy so two devices appealing the same decision
/// don't collide.
pub fn new_appeal_id() -> String {
    format!("cx:appeal:{}", crate::operation::uuid_v7())
}

/// Component: "Appeal this moderation decision" entrypoint. Renders near
/// a user-facing moderation outcome (deny / quarantine / require_review).
///
/// Props:
/// - `realm_id` — security boundary for the original decision.
/// - `appellant` — DID of the affected user (the local account).
/// - `decision_event_id` — the moderation decision being appealed.
/// - `target_ref` — pointer to the moderated content.
/// - `base_url` / `api_token` — for the API call.
/// - `current_state` — projection of the most recent appeal-lifecycle
///   event so the user sees `Submitted` / `Under review` / `Decided` /
///   `Closed` once the server roundtrip lands.
#[component]
pub fn AppealEntrypoint(
    realm_id: String,
    appellant: String,
    decision_event_id: String,
    target_ref: String,
    base_url: String,
    api_token: String,
    current_state: AppealState,
) -> Element {
    let mut reason = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut local_state = use_signal(|| current_state.clone());

    let state_label = match local_state() {
        AppealState::None => "Not yet appealed",
        AppealState::Submitted => "Submitted — awaiting review",
        AppealState::UnderReview => "Under review",
        AppealState::Decided { .. } => "Decided",
        AppealState::Closed => "Closed",
    };

    rsx! {
        div {
            class: "event",
            "data-testid": "moderation-appeal-entrypoint",
            role: "region",
            "aria-label": "Appeal this moderation decision",
            div { class: "event-head",
                span { "Appeal this moderation decision" }
                span { class: "badge", "cx.moderation.appeal.submit" }
            }
            div {
                class: "muted",
                "data-testid": "moderation-appeal-state",
                "{state_label}"
            }
            if matches!(local_state(), AppealState::None) {
                textarea {
                    "data-testid": "moderation-appeal-reason",
                    value: "{reason}",
                    placeholder: "Why should this decision be reconsidered? (required)",
                    oninput: move |evt| reason.set(evt.value()),
                }
                button {
                    class: "primary",
                    "data-testid": "moderation-appeal-submit",
                    disabled: submitting() || reason.read().trim().is_empty(),
                    onclick: move |_| {
                        let realm = realm_id.clone();
                        let appellant = appellant.clone();
                        let decision = decision_event_id.clone();
                        let target = target_ref.clone();
                        let base = base_url.clone();
                        let token = api_token.clone();
                        let reason_text = reason.read().trim().to_owned();
                        submitting.set(true);
                        status.set(String::new());
                        spawn(async move {
                            let appeal_id = new_appeal_id();
                            // TODO(round23-T06): once the blob upload path
                            // settles for appeal narratives in E2EE Realms,
                            // POST the reason as a `cx:blob:…` ref instead
                            // of inlining the string. For now we inline so
                            // server-side reducer testing has a payload to
                            // chew on.
                            let reason_ref = format!("inline:{reason_text}");
                            let op = match build_appeal_submit_op(
                                &realm,
                                &appellant,
                                &appeal_id,
                                &decision,
                                &target,
                                &reason_ref,
                            ) {
                                Ok(op) => op,
                                Err(err) => {
                                    status.set(format!("Appeal build failed: {err}"));
                                    submitting.set(false);
                                    return;
                                }
                            };
                            let envelope = op.build("yougen");
                            let result = with_authed_api(&base, token, |api| async move {
                                api.submit_event_envelope(&envelope).await
                            })
                            .await;
                            match result {
                                Ok(_) => {
                                    local_state.set(AppealState::Submitted);
                                    status.set(format!(
                                        "Appeal {appeal_id} submitted — server will surface status here once the review lands."
                                    ));
                                }
                                Err(err) => {
                                    status.set(format!("Appeal submit failed: {}", err.display()));
                                }
                            }
                            submitting.set(false);
                        });
                    },
                    if submitting() { "Submitting…" } else { "Appeal this decision" }
                }
            }
            if !status.read().is_empty() {
                div { class: "muted", "data-testid": "moderation-appeal-status", "{status}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appeal_state_from_kind_recognises_all_four_wire_kinds() {
        assert_eq!(
            AppealState::from_latest_event_kind("cx.moderation.appeal.submit", &json!({})),
            AppealState::Submitted
        );
        assert_eq!(
            AppealState::from_latest_event_kind("cx.moderation.appeal.review", &json!({})),
            AppealState::UnderReview
        );
        assert_eq!(
            AppealState::from_latest_event_kind(
                "cx.moderation.appeal.decision",
                &json!({"verdict": "uphold"}),
            ),
            AppealState::Decided {
                verdict: "uphold".to_owned()
            }
        );
        assert_eq!(
            AppealState::from_latest_event_kind("cx.moderation.appeal.close", &json!({})),
            AppealState::Closed
        );
    }

    #[test]
    fn build_appeal_submit_op_emits_canonical_kind() {
        let op = build_appeal_submit_op(
            "cx:space:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "cx:appeal:01904100-0000-7000-8000-000000000002",
            "cx:event:01904100-0000-7000-8000-000000000003",
            "cx:event:01904100-0000-7000-8000-000000000003",
            "inline:I was misidentified.",
        )
        .expect("build appeal op")
        .build("test-node");
        assert_eq!(op.kind, "cx.moderation.appeal.submit");
        assert_eq!(op.payload["schema"], "cx.schema.moderation_appeal.v1");
        assert!(op.payload["appeal_id"].is_string());
    }

    #[test]
    fn build_appeal_submit_op_rejects_bad_appeal_id() {
        let err = build_appeal_submit_op(
            "cx:space:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "appeal-1",
            "cx:event:01904100-0000-7000-8000-000000000003",
            "cx:event:01904100-0000-7000-8000-000000000003",
            "blob:reason",
        );
        assert!(err.is_err());
    }
}
