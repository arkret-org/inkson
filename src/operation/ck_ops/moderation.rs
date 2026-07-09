//! Moderation decision / appeal FSM builders.
//!
//! Daily moderation governance is authored as self-signed protocol
//! events submitted via `ck.self.events.command.submit`
//! (`POST /_arkret/self/events`); the product-admin moderation write path
//! is retired. The soland P2 reducer (`apply_moderation`) projects
//! these into `ck.component.moderation_state.v1` /
//! `ck.component.moderation.appeal.v1` and enforces the §5.5.2
//! separation-of-duties / atomicity constraints.

use serde_json::{Value, json};

use super::{OperationBuilder, did_id, payload_value, trim_realm_id};

/// Derive the `request_canonical_digest` the `moderation_decision_payload`
/// schema mandates (JCS SHA-256, `sha256:<64hex>`). inkson's reviewer
/// workbench seals decisions directly — there is no upstream Policy Server
/// request to hash — so the binding is a deterministic canonical digest
/// over the moderated target preview. It is stable and reproducible for
/// the exact `target_ref` being sealed.
fn decision_request_digest(target_ref: &str) -> anyhow::Result<arkret_sdk::Hash> {
    let digest = arkret_sdk::canonical::canonical_sha256(&json!({ "target_ref": target_ref }))
        .map_err(|err| anyhow::anyhow!("moderation decision request digest: {err}"))?;
    arkret_sdk::Hash::new(digest)
        .map_err(|err| anyhow::anyhow!("moderation decision request digest is not a Hash: {err}"))
}

/// `ck.moderation.decision` — seal a moderation disposition over
/// `target_ref` (the canonical `ck.component.moderation_state.v1` cell
/// subject). `decision` is the runtime verb from the closed schema enum
/// (`hard_deny` / `soft_deny` / `quarantine` / `require_review`). The
/// authoring `actor` is the sealed `issuer`; the decision Event's own id
/// is the reference later lift / appeal events resolve.
///
/// Uses the SDK `ModerationDecisionPayload` strong type (`deny_unknown_fields`)
/// so the wire body cannot drift from `event-payload.schema.json`.
pub fn moderation_decision(
    realm_id: &str,
    actor: &str,
    target_ref: &str,
    decision: &str,
    reason_code: &str,
) -> anyhow::Result<OperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let payload = arkret_sdk::ModerationDecisionPayload {
        target_ref: Value::String(target_ref.to_owned()),
        decision: decision.to_owned(),
        issuer: did_id(actor)?,
        request_canonical_digest: decision_request_digest(target_ref)?,
        action: None,
        reason_code: Some(reason_code.to_owned()),
        reason: None,
        policy_decision_ref: None,
        modify_decision_ref: None,
        effective_at: None,
        expires_at: None,
    };
    Ok(OperationBuilder::new(
        &realm,
        actor,
        arkret_sdk::events::kinds::EventKind::ModerationDecision,
    )
    .target_ref(target_ref)
    .body(payload_value(&payload, "moderation_decision payload")?))
}

/// `ck.moderation.decision.lift` — observed-remove / supersede a
/// previously sealed decision. The cell subject is `target_ref` (the same
/// moderated target as the original decision); `decision_ref` is the
/// `ck:event:` id of the decision Event whose sealed tag is removed.
///
/// Uses the SDK `ModerationDecisionLiftPayload` strong type.
pub fn moderation_decision_lift(
    realm_id: &str,
    actor: &str,
    target_ref: &str,
    decision_ref: &str,
    reason_code: &str,
) -> anyhow::Result<OperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let payload = arkret_sdk::ModerationDecisionLiftPayload {
        target_ref: Value::String(target_ref.to_owned()),
        decision_ref: Value::String(decision_ref.to_owned()),
        reason_code: Some(reason_code.to_owned()),
        reason: None,
        effective_at: None,
    };
    Ok(OperationBuilder::new(
        &realm,
        actor,
        arkret_sdk::events::kinds::EventKind::ModerationDecisionLift,
    )
    .target_ref(target_ref)
    .body(payload_value(&payload, "moderation_decision_lift payload")?))
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
        arkret_sdk::events::kinds::EventKind::ModerationAppealReview,
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
        arkret_sdk::events::kinds::EventKind::ModerationAppealDecision,
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
        arkret_sdk::events::kinds::EventKind::ModerationAppealClose,
    )
    .target_ref(appeal_id)
    .body(body)
}
