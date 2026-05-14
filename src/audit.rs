//! Audited E2EE event builders (`crypto-media/audited-e2ee.md`).
//!
//! Two hardening profiles sit on top of `cx.profile.e2ee_client.v1`:
//! - `cx.profile.attested_audit.e2ee.v1` — attested audit policy with
//!   forced `cx.audit.accessed` write on read.
//! - `cx.profile.disclosed_audit.e2ee.v1` — disclosed audit policy with
//!   `cx.audit.ryw_receipt` (read-your-write) per-actor receipts.
//!
//! Both kinds are already in `conformance::known_event_kinds`; this module
//! provides typed builders so call sites don't hand-roll the body shape.

use serde_json::{Value, json};

use crate::operation::OperationBuilder;

/// Spec-aligned audit policy mode for a Space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditPolicy {
    /// `attested_audit.e2ee.v1` — every successful decrypt writes
    /// `cx.audit.accessed`. Read clients fail closed if they cannot emit.
    Attested,
    /// `disclosed_audit.e2ee.v1` — every Space write produces a per-actor
    /// `cx.audit.ryw_receipt`. Receipt is actor-private; the audit channel is
    /// the read side.
    Disclosed,
}

impl AuditPolicy {
    pub fn profile_id(self) -> &'static str {
        match self {
            Self::Attested => "cx.profile.attested_audit.e2ee.v1",
            Self::Disclosed => "cx.profile.disclosed_audit.e2ee.v1",
        }
    }
}

/// Build a `cx.audit.accessed` event. Emitted by the reader after a
/// successful MLS decrypt under an attested audit policy.
///
/// `target_event_id` identifies the durable Event whose payload was read;
/// `device_id` is the reader's device DID.
pub fn build_audit_accessed(
    space_id: &str,
    actor: &str,
    target_event_id: &str,
    device_id: &str,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.audit.accessed")
        .target_ref(target_event_id)
        .body(json!({
            "target_event_id": target_event_id,
            "reader_device": device_id,
        }))
}

/// Build a `cx.audit.ryw_receipt` event. Emitted by the writer after a
/// disclosed audit policy commit; the receipt is actor-private.
pub fn build_audit_ryw_receipt(
    space_id: &str,
    actor: &str,
    source_event_id: &str,
    delivered_to_devices: Vec<String>,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.audit.ryw_receipt")
        .target_ref(source_event_id)
        .body(json!({
            "source_event_id": source_event_id,
            "delivered_to_devices": delivered_to_devices,
        }))
}

/// Build a `cx.identity.disclosure_policy` event — declares what a connection
/// holder may disclose about the principal. Spec: `identity-handles.md` §16.
///
/// `policy` is the structured policy document; the reducer enforces shape.
pub fn build_disclosure_policy(space_id: &str, actor: &str, policy: Value) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.identity.disclosure_policy").body(json!({
        "policy": policy,
    }))
}

/// Build a `cx.identity.presentation_request` event — request a verifiable
/// presentation from a connection holder.
pub fn build_presentation_request(
    space_id: &str,
    actor: &str,
    target: &str,
    requested_claims: Vec<String>,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.identity.presentation_request")
        .target_ref(target)
        .body(json!({
            "target": target,
            "requested_claims": requested_claims,
        }))
}

/// Build a `cx.identity.presentation_response` event — reply with a signed
/// verifiable presentation.
pub fn build_presentation_response(
    space_id: &str,
    actor: &str,
    request_id: &str,
    presentation: Value,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.identity.presentation_response")
        .target_ref(request_id)
        .body(json!({
            "request_id": request_id,
            "presentation": presentation,
        }))
}

/// Build a `cx.identity.disclosure_receipt` event — actor-private record of
/// what was disclosed and to whom (audit trail for the principal).
pub fn build_disclosure_receipt(
    space_id: &str,
    actor: &str,
    request_id: &str,
    counterparty: &str,
    disclosed_claims: Vec<String>,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.identity.disclosure_receipt")
        .target_ref(request_id)
        .body(json!({
            "request_id": request_id,
            "counterparty": counterparty,
            "disclosed_claims": disclosed_claims,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_accessed_emits_canonical_kind() {
        let op = build_audit_accessed(
            "cx:space:s1",
            "did:web:alice",
            "cx:event:abc",
            "did:key:zDevice",
        )
        .build("node");
        assert_eq!(op.op_type, "cx.audit.accessed");
        assert_eq!(op.body["target_event_id"], "cx:event:abc");
        assert_eq!(op.body["reader_device"], "did:key:zDevice");
    }

    #[test]
    fn audit_ryw_receipt_lists_devices() {
        let op = build_audit_ryw_receipt(
            "cx:space:s1",
            "did:web:alice",
            "cx:event:abc",
            vec!["did:key:zA".into(), "did:key:zB".into()],
        )
        .build("node");
        assert_eq!(op.op_type, "cx.audit.ryw_receipt");
        assert_eq!(op.body["delivered_to_devices"][1], "did:key:zB");
    }

    #[test]
    fn presentation_request_carries_claim_list() {
        let op = build_presentation_request(
            "cx:space:s1",
            "did:web:alice",
            "did:web:bob",
            vec!["display_name".into(), "avatar".into()],
        )
        .build("node");
        assert_eq!(op.op_type, "cx.identity.presentation_request");
        assert_eq!(op.body["requested_claims"][0], "display_name");
    }

    #[test]
    fn disclosure_receipt_records_counterparty() {
        let op = build_disclosure_receipt(
            "cx:space:s1",
            "did:web:alice",
            "cx:event:req",
            "did:web:bob",
            vec!["email".into()],
        )
        .build("node");
        assert_eq!(op.op_type, "cx.identity.disclosure_receipt");
        assert_eq!(op.body["counterparty"], "did:web:bob");
    }

    #[test]
    fn audit_policy_profile_ids_match_spec() {
        assert_eq!(
            AuditPolicy::Attested.profile_id(),
            "cx.profile.attested_audit.e2ee.v1"
        );
        assert_eq!(
            AuditPolicy::Disclosed.profile_id(),
            "cx.profile.disclosed_audit.e2ee.v1"
        );
    }
}
