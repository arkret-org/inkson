//! Audited E2EE event builders (`crypto-media/audited-e2ee.md`).
//!
//! Two hardening profiles sit on top of `ak.profile.e2ee_client.v1`:
//! - `ak.profile.attested_audit.e2ee.v1` — attested audit policy with forced `ak.audit.accessed`
//!   write on read.
//! - `ak.profile.disclosed_audit.e2ee.v1` — disclosed audit policy with `ak.audit.ryw_receipt`
//!   (read-your-write) per-actor receipts.
//!
//! Both kinds are already in the SDK event-kind registry; this module provides
//! typed builders so call sites don't hand-roll the body shape.

use crate::operation::TypedOperationBuilder;

/// Spec-aligned audit policy mode for a Realm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditPolicy {
    /// `attested_audit.e2ee.v1` — every successful decrypt writes
    /// `ak.audit.accessed`. Read clients fail closed if they cannot emit.
    Attested,
    /// `disclosed_audit.e2ee.v1` — accepted audit access/release writes are
    /// followed by a receipt from the Events API node, witness, or bound audit
    /// service before protected output. End-user clients do not self-issue it.
    Disclosed,
}

impl AuditPolicy {
    pub fn profile_id(self) -> &'static str {
        match self {
            Self::Attested => "ak.profile.attested_audit.e2ee.v1",
            Self::Disclosed => "ak.profile.disclosed_audit.e2ee.v1",
        }
    }
}

/// Build a `ak.audit.accessed` event. Emitted by the reader after a
/// successful MLS decrypt under an attested audit policy.
///
/// `target_event_id` identifies the durable Event whose payload was read;
/// `device_id` is the reader's device DID.
pub fn build_audit_accessed(
    realm_id: &str,
    actor: &str,
    target_event_id: &str,
    device_id: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    // The registered `audit_payload` schema (ak.schema.event_payload.v1
    // #/$defs/audit_payload) is strict `additionalProperties:false` and only
    // permits `target_ref`, `actor_id`, `purpose`, `accessed_at`. The reader
    // device is carried inside `purpose` (a free-form string) rather than as an
    // illegal top-level `reader_device` field, which the server rejects with
    // schema_violation.
    let payload = arkret_sdk::AuditAccessedPayload {
        access_kind: arkret_sdk::AuditAccessedKind::Other,
        writer_actor_id: crate::mls_api_helpers::principal_core_id(actor)?,
        target_actor_id: None,
        target_ref: target_event_id.into(),
        target_cell_id: None,
        paired_event_id: None,
        paired_event_digest: None,
        late_recovery_original_event_id: None,
        cell_head_before: None,
        cell_head_after: None,
        purpose: arkret_sdk::NonEmptyString::new(format!("e2ee_read;reader_device={device_id}"))
            .map_err(anyhow::Error::msg)?,
        accessed_at: crate::clock::now_utc_millis(),
        ryw_required: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::AuditAccessed>(
            realm_id, actor, payload,
        )
        .target_ref(target_event_id),
    )
}

/// Build the durable Event form of an `ak.audit.ryw_receipt` for a trusted
/// receipt issuer. Ordinary message writers MUST NOT use this as a post-send
/// acknowledgement; the receipt attests that its target audit Event is already
/// accepted.
pub fn build_audit_ryw_receipt(
    realm_id: &str,
    actor: &str,
    source_event_id: &str,
    delivered_to_devices: Vec<String>,
) -> anyhow::Result<TypedOperationBuilder> {
    // The registered `audit_payload` schema is strict `additionalProperties:false`
    // and only permits `target_ref`, `actor_id`, `purpose`, `accessed_at`. The
    // source event is carried as `target_ref`; the delivered-device set is folded
    // into `purpose` (free-form string) rather than illegal top-level
    // `source_event_id` / `delivered_to_devices` fields, which the server rejects
    // with `schema_violation`.
    let purpose = if delivered_to_devices.is_empty() {
        "ryw_receipt".to_owned()
    } else {
        format!(
            "ryw_receipt;delivered_to={}",
            delivered_to_devices.join(",")
        )
    };
    let payload = arkret_sdk::AuditPayload {
        target_ref: Some(source_event_id.into()),
        actor_id: Some(crate::mls_api_helpers::principal_core_id(actor)?),
        purpose: Some(purpose),
        accessed_at: Some(crate::clock::now_utc_millis()),
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::AuditRywReceipt>(
            realm_id, actor, payload,
        )
        .target_ref(source_event_id),
    )
}

/// Build a `ak.identity.presentation_request` event — request a verifiable
/// presentation from a connection holder.
///
/// `request_id` is the stable presentation correlation subject: the registered
/// contract derives the `ak.component.identity.presentation.v1` log cell from
/// it, and the response / disclosure receipt cite the same id. The registered
/// `identity_presentation_request_state_payload` is closed over
/// `{request_id, value, state, reason}`, so the product content travels inside
/// `value` rather than as sibling members.
pub fn build_presentation_request(
    realm_id: &str,
    actor: &str,
    request_id: &str,
    target: &str,
    requested_claims: Vec<String>,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::IdentityPresentationRequestStatePayload {
        request_id: arkret_sdk::NonEmptyString::new(request_id).map_err(anyhow::Error::msg)?,
        value: Some(serde_json::json!({
            "target": target,
            "requested_claims": requested_claims,
        })),
        state: None,
        reason: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::IdentityPresentationRequest>(
            realm_id, actor, payload,
        )
        .target_ref(request_id),
    )
}

/// Build a `ak.identity.disclosure_receipt` event — actor-private record of
/// what was disclosed and to whom (audit trail for the principal).
/// `holder_did` is the stable log subject the registered contract derives the
/// `ak.component.identity.disclosure_receipt.v1` cell from; the closed
/// `identity_disclosure_receipt_state_payload` carries everything else inside
/// `value`.
pub fn build_disclosure_receipt(
    realm_id: &str,
    actor: &str,
    holder_did: &str,
    request_id: &str,
    counterparty: &str,
    disclosed_claims: Vec<String>,
) -> anyhow::Result<TypedOperationBuilder> {
    let counterparty = crate::mls_api_helpers::principal_core_id(counterparty)?;
    let payload = arkret_sdk::IdentityDisclosureReceiptStatePayload {
        holder_principal_id: crate::mls_api_helpers::principal_core_id(holder_did)?,
        value: Some(serde_json::json!({
            "request_id": request_id,
            "counterparty": counterparty,
            "disclosed_claims": disclosed_claims,
        })),
        state: None,
        reason: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::IdentityDisclosureReceipt>(
            realm_id, actor, payload,
        )
        .target_ref(request_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_accessed_emits_canonical_kind() {
        let op = build_audit_accessed(
            "ak:realm:AedjkD9d4O8HsmPTELawvNXaIESdgksYx6jB4w3TZG0J",
            "did:web:alice",
            "ak:event:ANOufzo30HjlW4S8eBowzzay9mI2anxKRM5l1AUQ1pDE",
            "did:key:zDevice",
        )
        .unwrap()
        .build("node");
        assert_eq!(op.kind, "ak.audit.accessed");
        assert_eq!(
            op.payload["target_ref"],
            "ak:event:ANOufzo30HjlW4S8eBowzzay9mI2anxKRM5l1AUQ1pDE"
        );
        assert_eq!(op.payload["writer_actor_id"], "ak:did_core:web:alice");
        assert!(
            op.payload["purpose"]
                .as_str()
                .is_some_and(|p| p.contains("reader_device=did:key:zDevice"))
        );
        assert!(op.payload["accessed_at"].is_string());
        // No illegal top-level fields under the strict audit_payload schema.
        assert!(!op.payload.contains_key("reader_device"));
        assert!(!op.payload.contains_key("target_event_id"));
    }

    #[test]
    fn audit_ryw_receipt_lists_devices() {
        let op = build_audit_ryw_receipt(
            "ak:realm:AedjkD9d4O8HsmPTELawvNXaIESdgksYx6jB4w3TZG0J",
            "did:web:alice",
            "ak:event:ANOufzo30HjlW4S8eBowzzay9mI2anxKRM5l1AUQ1pDE",
            vec!["did:key:zA".into(), "did:key:zB".into()],
        )
        .unwrap()
        .build("node");
        assert_eq!(op.kind, "ak.audit.ryw_receipt");
        assert_eq!(
            op.payload["target_ref"],
            "ak:event:ANOufzo30HjlW4S8eBowzzay9mI2anxKRM5l1AUQ1pDE"
        );
        assert_eq!(op.payload["actor_id"], "ak:did_core:web:alice");
        assert!(
            op.payload["purpose"]
                .as_str()
                .is_some_and(|p| p.contains("did:key:zA") && p.contains("did:key:zB"))
        );
        assert!(op.payload["accessed_at"].is_string());
        // No illegal top-level fields under the strict audit_payload schema.
        assert!(!op.payload.contains_key("delivered_to_devices"));
        assert!(!op.payload.contains_key("source_event_id"));
    }

    #[test]
    fn ordinary_chat_send_does_not_self_issue_audit_ryw_receipts() {
        let composer = include_str!("views/chat/composer.rs");
        assert!(
            !composer.contains("build_audit_ryw_receipt"),
            "ordinary message writers are not trusted audit receipt issuers"
        );
    }

    /// The closed `identity_presentation_request_state_payload` keeps only
    /// `request_id` at the top level; the requested claims are product content
    /// inside `value`, and `request_id` is what the registered contract turns
    /// into the log cell subject.
    #[test]
    fn presentation_request_carries_claim_list_under_the_correlation_subject() {
        let op = build_presentation_request(
            "ak:realm:AedjkD9d4O8HsmPTELawvNXaIESdgksYx6jB4w3TZG0J",
            "did:web:alice",
            "ak:event:AUN9rLfFy2ZZ0Q_Pb0Ceep1zwqVi-IUSNePtOMdV3dhj",
            "did:web:bob",
            vec!["display_name".into(), "avatar".into()],
        )
        .unwrap()
        .build("node");
        assert_eq!(op.kind, "ak.identity.presentation_request");
        assert_eq!(
            op.payload["request_id"],
            "ak:event:AUN9rLfFy2ZZ0Q_Pb0Ceep1zwqVi-IUSNePtOMdV3dhj"
        );
        assert_eq!(op.payload["value"]["requested_claims"][0], "display_name");
        let writes = crate::operation::direct_registered_cell_writes(&op).unwrap();
        assert_eq!(
            writes[0].cell.as_str(),
            "ak:cell:ak.component.identity.presentation.v1:ak:event:AUN9rLfFy2ZZ0Q_Pb0Ceep1zwqVi-IUSNePtOMdV3dhj"
        );
    }

    /// The receipt's log subject is the holder DID, not the request id: one
    /// holder accumulates an append-only disclosure history across requests.
    #[test]
    fn disclosure_receipt_records_counterparty_under_the_holder_subject() {
        let op = build_disclosure_receipt(
            "ak:realm:AedjkD9d4O8HsmPTELawvNXaIESdgksYx6jB4w3TZG0J",
            "did:web:alice",
            "did:web:alice",
            "ak:event:AUN9rLfFy2ZZ0Q_Pb0Ceep1zwqVi-IUSNePtOMdV3dhj",
            "did:web:bob",
            vec!["email".into()],
        )
        .unwrap()
        .build("node");
        assert_eq!(op.kind, "ak.identity.disclosure_receipt");
        assert_eq!(op.payload["holder_principal_id"], "ak:did_core:web:alice");
        assert_eq!(op.payload["value"]["counterparty"], "ak:did_core:web:bob");
        let writes = crate::operation::direct_registered_cell_writes(&op).unwrap();
        assert_eq!(
            writes[0].cell.as_str(),
            "ak:cell:ak.component.identity.disclosure_receipt.v1:ak:did_core:web:alice"
        );
    }

    #[test]
    fn audit_policy_profile_ids_match_spec() {
        assert_eq!(
            AuditPolicy::Attested.profile_id(),
            "ak.profile.attested_audit.e2ee.v1"
        );
        assert_eq!(
            AuditPolicy::Disclosed.profile_id(),
            "ak.profile.disclosed_audit.e2ee.v1"
        );
    }
}
