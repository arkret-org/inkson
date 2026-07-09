//! Moderation decision / appeal FSM builders.
//!
//! Daily moderation governance is authored as self-signed protocol
//! events submitted via `ck.self.events.command.submit`
//! (`POST /_cokret/self/events`); the product-admin moderation write path
//! is retired. The soland P2 reducer (`apply_moderation`) projects
//! these into `ck.component.moderation_state.v1` /
//! `ck.component.moderation.appeal.v1` and enforces the §5.5.2
//! separation-of-duties / atomicity constraints.

use serde_json::json;

use super::{OperationBuilder, trim_realm_id};

/// `ck.moderation.decision` — seal a moderation disposition. Writes the
/// `moderation_state` cell keyed by `decision_id`. The reducer reads
/// `decision_id` + `issuer` (here the authoring `actor`) and carries the
/// `target_ref` / `verdict` snapshot so the appeal SoD reverse-lookup
/// resolves the original issuer.
pub fn moderation_decision(
    realm_id: &str,
    actor: &str,
    decision_id: &str,
    target_ref: &str,
    verdict: &str,
    reason_code: &str,
) -> OperationBuilder {
    let realm = trim_realm_id(realm_id);
    OperationBuilder::new(
        &realm,
        actor,
        cokret_sdk::events::kinds::EventKind::ModerationDecision,
    )
    .target_ref(target_ref)
    .body(json!({
        "decision_id": decision_id,
        "realm_id": realm,
        "issuer": actor,
        "target_ref": target_ref,
        "verdict": verdict,
        "reason_code": reason_code,
        "decided_at": crate::clock::now_rfc3339_secs(),
    }))
}

/// `ck.moderation.decision.lift` — observed-remove / supersede a
/// previously sealed decision. Cell subject is `decision_ref` (the
/// `decision_id` of the decision being lifted).
pub fn moderation_decision_lift(
    realm_id: &str,
    actor: &str,
    decision_ref: &str,
    reason_code: &str,
) -> OperationBuilder {
    let realm = trim_realm_id(realm_id);
    OperationBuilder::new(
        &realm,
        actor,
        cokret_sdk::events::kinds::EventKind::ModerationDecisionLift,
    )
    .target_ref(decision_ref)
    .body(json!({
        "decision_ref": decision_ref,
        "realm_id": realm,
        "issuer": actor,
        "reason_code": reason_code,
        "lifted_at": crate::clock::now_rfc3339_secs(),
    }))
}

/// `ck.moderation.appeal.review` — reviewer takes an appeal under
/// review (`submitted → under_review`). `reviewer` is the authoring
/// actor; the reducer rejects with `appeal_self_review_forbidden` when
/// it equals the appealed decision's issuer.
pub fn moderation_appeal_review(
    realm_id: &str,
    actor: &str,
    appeal_id: &str,
    notes_ref: Option<&str>,
) -> OperationBuilder {
    let realm = trim_realm_id(realm_id);
    let mut body = json!({
        "appeal_id": appeal_id,
        "realm_id": realm,
        "reviewer": actor,
        "reviewed_at": crate::clock::now_rfc3339_secs(),
    });
    if let Some(notes_ref) = notes_ref {
        body["notes_ref"] = json!(notes_ref);
    }
    OperationBuilder::new(
        &realm,
        actor,
        cokret_sdk::events::kinds::EventKind::ModerationAppealReview,
    )
    .target_ref(appeal_id)
    .body(body)
}

/// `ck.moderation.appeal.decision` — reviewer verdict
/// (`under_review → decided`). `verdict` ∈ {uphold, overturn, modify}.
/// `overturn` MUST be paired in the same ordered submit batch with a
/// [`moderation_decision_lift`] over the appealed `decision_ref`;
/// `modify` MUST name the replacement decision via `modify_decision_ref`
/// (and pair the new [`moderation_decision`]). The caller owns batch
/// ordering; this builder only mints the event.
pub fn moderation_appeal_decision(
    realm_id: &str,
    actor: &str,
    appeal_id: &str,
    verdict: &str,
    reason_text_ref: &str,
    modify_decision_ref: Option<&str>,
) -> OperationBuilder {
    let realm = trim_realm_id(realm_id);
    let mut body = json!({
        "appeal_id": appeal_id,
        "realm_id": realm,
        "reviewer": actor,
        "verdict": verdict,
        "reason_text_ref": reason_text_ref,
        "decided_at": crate::clock::now_rfc3339_secs(),
    });
    if let Some(modify_decision_ref) = modify_decision_ref {
        body["modify_decision_ref"] = json!(modify_decision_ref);
    }
    OperationBuilder::new(
        &realm,
        actor,
        cokret_sdk::events::kinds::EventKind::ModerationAppealDecision,
    )
    .target_ref(appeal_id)
    .body(body)
}

/// `ck.moderation.appeal.close` — terminal close of an appeal from
/// submitted / under_review / decided. `closer` is the authoring actor
/// (reviewer close or appellant withdrawal — the reducer authorizes the
/// withdrawal path by `closer == appellant`).
pub fn moderation_appeal_close(
    realm_id: &str,
    actor: &str,
    appeal_id: &str,
    close_reason: Option<&str>,
) -> OperationBuilder {
    let realm = trim_realm_id(realm_id);
    let mut body = json!({
        "appeal_id": appeal_id,
        "realm_id": realm,
        "closer": actor,
        "closed_at": crate::clock::now_rfc3339_secs(),
    });
    if let Some(close_reason) = close_reason {
        body["close_reason"] = json!(close_reason);
    }
    OperationBuilder::new(
        &realm,
        actor,
        cokret_sdk::events::kinds::EventKind::ModerationAppealClose,
    )
    .target_ref(appeal_id)
    .body(body)
}
