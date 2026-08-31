//! Round R2/R3 (T06) — moderation appeal user strand.
//!
//! Per `governance/content-moderation.md` §4 (Round R2/R3), every
//! moderation decision the reducer emits MUST give the affected user an
//! "Appeal this decision" entrypoint. The four-event lifecycle is:
//!
//! - `ak.moderation.appeal.submit`   — user files the appeal
//! - `ak.moderation.appeal.review`   — reviewer takes the file
//! - `ak.moderation.appeal.decision` — reviewer decides (uphold / overturn / modify)
//! - `ak.moderation.appeal.close`    — appeal terminal
//!
//! This module exposes:
//!
//! 1. `AppealState` — UI-side projection of the four wire states the user sees (submitted /
//!    under_review / decided / closed).
//! 2. `AppealSubmitter` component — renders the entrypoint button near a moderation decision and
//!    submits the `ak.moderation.appeal.submit` event via the durable event channel.
//!
//! The full reviewer surface (Review/Decision/Close authoring) is admin
//! scope and lives in `realm_admin.rs` once wired. See
//! `// TODO(moderation-appeal-blob-upload)` markers below for deferred pieces.

use arkret_sdk::AppealDecision;
use arkret_wire::event_kind_str;
use chrono::Utc;
use dioxus::prelude::*;

use crate::operation::trim_realm_id;
use crate::transport::auth::with_authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

/// User-facing projection of the four moderation appeal wire states.
///
/// Wire kinds (Round R2/R3):
/// - `ak.moderation.appeal.submit`   → [`AppealState::Submitted`]
/// - `ak.moderation.appeal.review`   → [`AppealState::UnderReview`]
/// - `ak.moderation.appeal.decision` → [`AppealState::Decided { .. }`]
/// - `ak.moderation.appeal.close`    → [`AppealState::Closed`]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum AppealState {
    None,
    Submitted,
    UnderReview,
    Decided { decision: AppealDecision },
    Closed,
}

impl AppealState {
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

/// Construct the canonical `ak.moderation.appeal.submit` event payload as
/// a typed Event builder. The wire shape matches
/// [`arkret_sdk::AppealSubmitPayload`] / `ak.schema.moderation_appeal.v1`.
///
/// Inputs:
/// - `decision_event_id` — the `ak:event:` id of the original moderation decision being appealed
///   (used as `decision_ref`).
/// - `target_ref` — opaque pointer to the moderated content (`ak:event:…` for a message,
///   `ak:strand:…` for a strand, etc.).
/// - `reason_text_ref` — blob ref or inline string carrying the appeal narrative (server may
///   require a `ak:blob:…` ref for E2EE Realms).
pub fn build_appeal_submit_op(
    realm_id: &str,
    appellant: &str,
    decision_event_id: &str,
    target_ref: &str,
    reason_text_ref: &str,
) -> anyhow::Result<crate::operation::TypedOperationBuilder> {
    let realm_id = trim_realm_id(realm_id);
    let payload = arkret_sdk::AppealSubmitPayload {
        realm_id: arkret_sdk::RealmId::new(realm_id.clone())
            .map_err(|err| anyhow::anyhow!("invalid realm_id: {err}"))?,
        decision_ref: arkret_sdk::EventId::new(decision_event_id)
            .map_err(|err| anyhow::anyhow!("invalid decision_event_id: {err}"))?,
        target_ref: target_ref.to_owned(),
        appellant_id: crate::mls_api_helpers::principal_core_id(appellant)
            .map_err(|err| anyhow::anyhow!("invalid appellant did: {err}"))?,
        reason_text_ref: reason_text_ref.to_owned(),
        evidence_refs: Vec::new(),
        evidence_visibility: None,
        created_at: Utc::now(),
    };
    // Validate via the SDK's oneOf-aware checker before serialization so a
    // future evolution of the payload (Decision::Modify needs a
    // modify_decision_ref, etc.) can't slip past.
    arkret_sdk::ModerationAppealPayload::Submit(payload.clone()).validate_minimal()?;

    Ok(
        crate::operation::TypedOperationBuilder::new::<
            arkret_sdk::event_spec::ModerationAppealSubmit,
        >(&realm_id, appellant, payload)
        .target_ref(decision_event_id),
    )
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
    api_token: String,
    current_state: AppealState,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
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
                span { class: "badge", {event_kind_str::MODERATION_APPEAL_SUBMIT} }
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
                            // TODO(moderation-appeal-blob-upload): once the blob upload path
                            // settles for appeal narratives in E2EE Realms,
                            // POST the reason as a `ak:blob:…` ref instead
                            // of inlining the string. For now we inline so
                            // server-side reducer testing has a payload to
                            // chew on.
                            let reason_ref = format!("inline:{reason_text}");
                            let op = match build_appeal_submit_op(
                                &realm,
                                &appellant,
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
                            let envelope = match op.build_sdk_event("inkson") {
                                Ok(envelope) => envelope,
                                Err(err) => {
                                    status.set(format!("Appeal build failed: {err}"));
                                    submitting.set(false);
                                    return;
                                }
                            };
                            // The Appeal is named by its own create Event, so its id
                            // exists only once that Event is accepted.
                            let result = with_authed_api(&base, token, |api| async move {
                                api.event_submitter()?.submit_sdk_event(&envelope).await
                            })
                            .await;
                            match result {
                                Ok(accepted) => {
                                    local_state.set(AppealState::Submitted);
                                    let appeal_id = arkret_sdk::EventId::new(accepted.event_id)
                                        .map(|event_id| {
                                            arkret_sdk::TypedAppealId::from_event_id(&event_id)
                                                .to_string()
                                        })
                                        .unwrap_or_default();
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
    use super::*;

    #[test]
    fn build_appeal_submit_op_emits_canonical_kind() {
        let op = build_appeal_submit_op(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "did:web:alice.example",
            "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "inline:I was misidentified.",
        )
        .expect("build appeal op")
        .build("test-node");
        assert_eq!(op.kind(), "ak.moderation.appeal.submit");
        assert_eq!(
            op.payload()["realm_id"],
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        );
        assert!(!op.payload().contains_key("appeal_id"));
        assert!(!op.payload().contains_key("schema"));
        let registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
            .unwrap()
            .unwrap();
        registry
            .validate_value(
                "ak.schema.moderation_appeal.v1#/$defs/submit_payload",
                &serde_json::to_value(op.payload()).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn build_appeal_submit_op_rejects_bad_decision_event_id() {
        let err = build_appeal_submit_op(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "did:web:alice.example",
            "decision-1",
            "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "blob:reason",
        );
        assert!(err.is_err());
    }
}
