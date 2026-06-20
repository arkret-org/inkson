//! Round R2/R3 (T06) — moderation appeal user strand.
//!
//! Per `governance/content-moderation.md` §4 (Round R2/R3), every
//! moderation decision the reducer emits MUST give the affected user an
//! "Appeal this decision" entrypoint. The four-event lifecycle is:
//!
//! - `ck.moderation.appeal.submit`   — user files the appeal
//! - `ck.moderation.appeal.review`   — reviewer takes the file
//! - `ck.moderation.appeal.decision` — reviewer decides (uphold / overturn / modify)
//! - `ck.moderation.appeal.close`    — appeal terminal
//!
//! This module exposes:
//!
//! 1. `AppealState` — UI-side projection of the four wire states the user sees (submitted /
//!    under_review / decided / closed).
//! 2. `AppealSubmitter` component — renders the entrypoint button near a moderation decision and
//!    submits the `ck.moderation.appeal.submit` event via the durable event channel.
//!
//! The full reviewer surface (Review/Decision/Close authoring) is admin
//! scope and lives in `realm_admin.rs` once wired. See
//! `// TODO(round23-T06)` markers below for the deferred pieces.

use chrono::Utc;
use dioxus::prelude::*;
use serde_json::Value;

use crate::operation::{OperationBuilder, trim_realm_id};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::textarea::Textarea;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// User-facing projection of the four moderation appeal wire states.
///
/// Wire kinds (Round R2/R3):
/// - `ck.moderation.appeal.submit`   → [`AppealState::Submitted`]
/// - `ck.moderation.appeal.review`   → [`AppealState::UnderReview`]
/// - `ck.moderation.appeal.decision` → [`AppealState::Decided { .. }`]
/// - `ck.moderation.appeal.close`    → [`AppealState::Closed`]
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
            "ck.moderation.appeal.submit" => Self::Submitted,
            "ck.moderation.appeal.review" => Self::UnderReview,
            "ck.moderation.appeal.decision" => {
                let verdict = payload
                    .get("verdict")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_owned();
                Self::Decided { verdict }
            }
            "ck.moderation.appeal.close" => Self::Closed,
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

/// Construct the canonical `ck.moderation.appeal.submit` event payload as
/// an [`OperationBuilder`]. The wire shape matches
/// [`cokret_sdk::AppealSubmitPayload`] / `ck.schema.moderation_appeal.v1`.
///
/// Inputs:
/// - `decision_event_id` — the `ck:event:` id of the original moderation decision being appealed
///   (used as `decision_ref`).
/// - `target_ref` — opaque pointer to the moderated content (`ck:event:…` for a message,
///   `ck:strand:…` for a strand, etc.).
/// - `reason_text_ref` — blob ref or inline string carrying the appeal narrative (server may
///   require a `ck:blob:…` ref for E2EE Realms).
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
    // enforces the `ck:appeal:<uuidv7>` shape.
    let typed_appeal_id = cokret_sdk::TypedAppealId::new(appeal_id)
        .map_err(|err| anyhow::anyhow!("invalid appeal_id: {err}"))?;
    let realm_id = trim_realm_id(realm_id);
    let payload = cokret_sdk::AppealSubmitPayload {
        appeal_id: typed_appeal_id.clone(),
        realm_id: cokret_sdk::RealmId::new(realm_id.clone())
            .map_err(|err| anyhow::anyhow!("invalid realm_id: {err}"))?,
        decision_ref: cokret_sdk::EventId::new(decision_event_id)
            .map_err(|err| anyhow::anyhow!("invalid decision_event_id: {err}"))?,
        target_ref: target_ref.to_owned(),
        appellant: cokret_sdk::Did::new(appellant)
            .map_err(|err| anyhow::anyhow!("invalid appellant did: {err}"))?,
        reason_text_ref: reason_text_ref.to_owned(),
        evidence_refs: Vec::new(),
        evidence_visibility: None,
        created_at: Utc::now(),
    };
    // Validate via the SDK's oneOf-aware checker before serialization so a
    // future evolution of the payload (Decision::Modify needs a
    // modify_decision_ref, etc.) can't slip past.
    cokret_sdk::ModerationAppealPayload::Submit(payload.clone()).validate_minimal()?;

    let body = serde_json::to_value(&payload)?;
    Ok(
        OperationBuilder::new(&realm_id, appellant, "ck.moderation.appeal.submit")
            .target_ref(decision_event_id)
            .body(body),
    )
}

/// Build a fresh `ck:appeal:<uuidv7>` id for a new appeal. UUIDv7 inherits
/// process clock entropy so two devices appealing the same decision
/// don't collide.
pub fn new_appeal_id() -> String {
    format!("ck:appeal:{}", crate::operation::uuid_v7())
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
/// - `current_state` — projection of the most recent appeal-lifecycle event so the user sees
///   `Submitted` / `Under review` / `Decided` / `Closed` once the server roundtrip lands.
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
                span { class: "badge", "ck.moderation.appeal.submit" }
            }
            div {
                class: "muted",
                "data-testid": "moderation-appeal-state",
                "{state_label}"
            }
            if matches!(local_state(), AppealState::None) {
                Textarea {
                    "data-testid": "moderation-appeal-reason",
                    value: "{reason}",
                    placeholder: "Why should this decision be reconsidered? (required)",
                    oninput: move |event: FormEvent| reason.set(event.value()),
                }
                Button {
                    variant: ButtonVariant::Primary,
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
                            // POST the reason as a `ck:blob:…` ref instead
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
                            let envelope = match op.build_sdk_event("yougen") {
                                Ok(envelope) => envelope,
                                Err(err) => {
                                    status.set(format!("Appeal build failed: {err}"));
                                    submitting.set(false);
                                    return;
                                }
                            };
                            let result = with_authed_api(&base, token, |api| async move {
                                api.submit_sdk_event(&envelope).await
                            })
                            .await;
                            match result {
                                Ok(_) => {
                                    local_state.set(AppealState::Submitted);
                                    status.set(format!(
                                        "Appeal {} submitted — server will surface status here once the review lands.",
                                        short_protocol_id(&appeal_id)
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
    use serde_json::json;

    use super::*;

    #[test]
    fn appeal_state_from_kind_recognises_all_four_wire_kinds() {
        assert_eq!(
            AppealState::from_latest_event_kind("ck.moderation.appeal.submit", &json!({})),
            AppealState::Submitted
        );
        assert_eq!(
            AppealState::from_latest_event_kind("ck.moderation.appeal.review", &json!({})),
            AppealState::UnderReview
        );
        assert_eq!(
            AppealState::from_latest_event_kind(
                "ck.moderation.appeal.decision",
                &json!({"verdict": "uphold"}),
            ),
            AppealState::Decided {
                verdict: "uphold".to_owned()
            }
        );
        assert_eq!(
            AppealState::from_latest_event_kind("ck.moderation.appeal.close", &json!({})),
            AppealState::Closed
        );
    }

    #[test]
    fn build_appeal_submit_op_emits_canonical_kind() {
        let op = build_appeal_submit_op(
            "ck:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:appeal:01904100-0000-7000-8000-000000000002",
            "ck:event:01904100-0000-7000-8000-000000000003",
            "ck:event:01904100-0000-7000-8000-000000000003",
            "inline:I was misidentified.",
        )
        .expect("build appeal op")
        .build("test-node");
        assert_eq!(op.kind, "ck.moderation.appeal.submit");
        assert_eq!(
            op.payload["realm_id"],
            "ck:realm:01904100-0000-7000-8000-000000000001"
        );
        assert!(op.payload["appeal_id"].is_string());
        assert!(op.payload.get("schema").is_none());
        let registry = cokret_sdk::schema::schema_registry_from_default_spec_artifacts()
            .unwrap()
            .unwrap();
        registry
            .validate_value(
                "ck.schema.moderation_appeal.v1#/$defs/submit_payload",
                &op.payload,
            )
            .unwrap();
    }

    #[test]
    fn build_appeal_submit_op_rejects_bad_appeal_id() {
        let err = build_appeal_submit_op(
            "ck:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "appeal-1",
            "ck:event:01904100-0000-7000-8000-000000000003",
            "ck:event:01904100-0000-7000-8000-000000000003",
            "blob:reason",
        );
        assert!(err.is_err());
    }
}
