//! Moderation decision / appeal FSM builders.
//!
//! Daily moderation governance is authored as self-signed protocol
//! events submitted via `ak.self.events.command.submit`
//! (`POST /_arkret/self/events`); the product-admin moderation write path
//! is retired. The soland P2 reducer (`apply_moderation`) projects
//! these into `ak.component.moderation_state.v1` /
//! `ak.component.moderation.appeal.v1` and enforces the §5.5.2
//! separation-of-duties / atomicity constraints.

use serde_json::json;

use super::{TypedOperationBuilder, did_id, trim_realm_id};

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

/// `ak.moderation.decision` — seal a moderation disposition over
/// `target_ref` (the canonical `ak.component.moderation_state.v1` cell
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
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let payload = arkret_sdk::ModerationDecisionPayload {
        target_ref: target_ref.to_owned(),
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
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ModerationDecision>(
            &realm, actor, payload,
        )
        .target_ref(target_ref),
    )
}

/// `ak.moderation.decision.lift` — observed-remove / supersede a
/// previously sealed decision. The cell subject is `target_ref` (the same
/// moderated target as the original decision); `decision_ref` is the
/// `ak:event:` id of the decision Event whose sealed tag is removed.
///
/// Uses the SDK `ModerationDecisionLiftPayload` strong type.
pub fn moderation_decision_lift(
    realm_id: &str,
    actor: &str,
    target_ref: &str,
    decision_ref: &str,
    reason_code: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let payload = arkret_sdk::ModerationDecisionLiftPayload {
        target_ref: target_ref.to_owned(),
        decision_ref: arkret_sdk::EventId::new(decision_ref.to_owned())?,
        reason_code: Some(reason_code.to_owned()),
        reason: None,
        effective_at: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ModerationDecisionLift>(
            &realm, actor, payload,
        )
        .target_ref(target_ref),
    )
}

/// `ak.moderation.appeal.review` — reviewer takes an appeal under
/// review (`submitted → under_review`). `reviewer` is the authoring
/// actor; the reducer rejects with `appeal_self_review_forbidden` when
/// it equals the appealed decision's issuer.
pub fn moderation_appeal_review(
    realm_id: &str,
    actor: &str,
    appeal_id: &str,
    notes_ref: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let payload = arkret_sdk::AppealReviewPayload {
        appeal_id: arkret_sdk::TypedAppealId::new(appeal_id.to_owned())?,
        realm_id: arkret_sdk::RealmId::new(realm.clone())?,
        reviewer: did_id(actor)?,
        reviewed_at: crate::clock::now_utc_millis(),
        notes_ref: notes_ref.map(ToOwned::to_owned),
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ModerationAppealReview>(
            &realm, actor, payload,
        )
        .target_ref(appeal_id),
    )
}

/// `ak.moderation.appeal.decision` — reviewer verdict
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
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let verdict = match verdict {
        "uphold" => arkret_sdk::AppealVerdict::Uphold,
        "overturn" => arkret_sdk::AppealVerdict::Overturn,
        "modify" => arkret_sdk::AppealVerdict::Modify,
        other => anyhow::bail!("invalid moderation appeal verdict {other:?}"),
    };
    let payload = arkret_sdk::AppealDecisionPayload {
        appeal_id: arkret_sdk::TypedAppealId::new(appeal_id.to_owned())?,
        realm_id: arkret_sdk::RealmId::new(realm.clone())?,
        reviewer: did_id(actor)?,
        verdict,
        reason_text_ref: reason_text_ref.to_owned(),
        modify_decision_ref: modify_decision_ref
            .map(|event_id| arkret_sdk::EventId::new(event_id.to_owned()))
            .transpose()?,
        decided_at: crate::clock::now_utc_millis(),
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ModerationAppealDecision>(
            &realm, actor, payload,
        )
        .target_ref(appeal_id),
    )
}

/// `ak.moderation.appeal.close` — terminal close of an appeal from
/// submitted / under_review / decided. `closer` is the authoring actor
/// (reviewer close or appellant withdrawal — the reducer authorizes the
/// withdrawal path by `closer == appellant`).
pub fn moderation_appeal_close(
    realm_id: &str,
    actor: &str,
    appeal_id: &str,
    close_reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let payload = arkret_sdk::AppealClosePayload {
        appeal_id: arkret_sdk::TypedAppealId::new(appeal_id.to_owned())?,
        realm_id: arkret_sdk::RealmId::new(realm.clone())?,
        closer: did_id(actor)?,
        closed_at: crate::clock::now_utc_millis(),
        auto_closed: false,
        close_reason: close_reason.map(ToOwned::to_owned),
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ModerationAppealClose>(
            &realm, actor, payload,
        )
        .target_ref(appeal_id),
    )
}
