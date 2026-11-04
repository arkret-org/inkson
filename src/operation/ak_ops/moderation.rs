//! Moderation decision builders.
//!
//! Daily moderation governance is authored as self-signed protocol
//! events submitted via `ak.self.events.command.submit.v1`
//! (`POST /_arkret/self/events`); the product-admin moderation write path
//! is retired. The coland P2 reducer (`apply_moderation`) projects
//! these into `ak.component.moderation_state.v1`.

use serde_json::json;

use super::{TypedOperationBuilder, did_id, trim_realm_id};

/// Derive the `request_canonical_digest` the `moderation_decision_payload`
/// schema mandates (JCS SHA-256, `sha256:<64hex>`). The reviewer workbench
/// seals decisions directly, so the binding is a deterministic canonical digest
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
/// is the reference later lift events resolve.
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
        issuer_id: did_id(actor)?,
        request_canonical_digest: decision_request_digest(target_ref)?,
        action: None,
        reason_code: Some(reason_code.to_owned()),
        reason: None,
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
pub(crate) fn moderation_decision_lift(
    realm_id: &str,
    actor: &str,
    target_ref: &str,
    decision_ref: &str,
    reason_code: &str,
    current: &crate::event_submit::VerifiedModerationCurrent,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let decision_ref = arkret_sdk::EventId::new(decision_ref.to_owned())?;
    let payload = arkret_sdk::ModerationDecisionLiftPayload {
        target_ref: target_ref.to_owned(),
        expected_revision: current.revision_for_decision(target_ref, &decision_ref)?,
        decision_ref,
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

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::exact_current_state::{
        CanonicalEventDot, ModerationAssertionValue, ModerationDecisionEntry,
    };

    use super::*;

    const REALM: &str = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    const TARGET: &str = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    const DECISION: &str = "ak:event:ARn9Y97Ha81FH12YY8HLiDixId_wA5Wx2c25p82mJcJ5";

    fn revision() -> arkret_wire::CurrentRevision {
        arkret_wire::CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
            stream_position: 9,
        }
    }

    fn decision_entry() -> ModerationDecisionEntry {
        let decision_ref = arkret_sdk::EventId::new(DECISION).unwrap();
        let value = arkret_sdk::ModerationDecisionPayload {
            target_ref: TARGET.to_owned(),
            decision: "quarantine".to_owned(),
            issuer_id: arkret_sdk::DidCoreId::new("ak:did_core:web:moderator.example").unwrap(),
            request_canonical_digest: arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32)))
                .unwrap(),
            action: None,
            reason_code: Some("policy_violation".to_owned()),
            reason: None,
            effective_at: None,
            expires_at: None,
        };
        ModerationDecisionEntry {
            tag_id: CanonicalEventDot::new(decision_ref, 0).unwrap(),
            value: ModerationAssertionValue::Decision(value),
        }
    }

    #[test]
    fn lift_uses_exact_present_revision_and_current_decision() {
        let revision = revision();
        let current = crate::event_submit::VerifiedModerationCurrent::for_test(
            TARGET,
            revision.clone(),
            vec![decision_entry()],
        );
        let operation = moderation_decision_lift(
            REALM,
            "did:web:moderator.example",
            TARGET,
            DECISION,
            "reviewer_lift",
            &current,
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();
        let payload = operation
            .typed_payload::<arkret_wire::event_spec::ModerationDecisionLift>()
            .unwrap();
        assert_eq!(payload.expected_revision, revision);
        assert_eq!(payload.decision_ref.as_str(), DECISION);
    }

    #[test]
    fn lift_rejects_decision_absent_from_exact_current_assertions() {
        let current = crate::event_submit::VerifiedModerationCurrent::for_test(
            TARGET,
            revision(),
            Vec::new(),
        );
        let error = moderation_decision_lift(
            REALM,
            "did:web:moderator.example",
            TARGET,
            DECISION,
            "reviewer_lift",
            &current,
        )
        .expect_err("an absent decision must fail closed");
        assert!(error.to_string().contains("not present"));
    }
}
