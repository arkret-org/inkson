//! Audited E2EE event builders (`crypto-media/audited-e2ee.md`).
//!
//! Two hardening profiles sit on top of `cx.profile.e2ee_client.v1`:
//! - `cx.profile.attested_audit.e2ee.v1` — attested audit policy with forced `cx.audit.accessed`
//!   write on read.
//! - `cx.profile.disclosed_audit.e2ee.v1` — disclosed audit policy with `cx.audit.ryw_receipt`
//!   (read-your-write) per-actor receipts.
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
    // The registered `audit_payload` schema (cx.schema.event_payload.v1
    // #/$defs/audit_payload) is strict `additionalProperties:false` and only
    // permits `target_ref`, `actor_id`, `purpose`, `accessed_at`. The reader
    // device is carried inside `purpose` (a free-form string) rather than as an
    // illegal top-level `reader_device` field, which the server rejects with
    // schema_violation.
    OperationBuilder::new(space_id, actor, "cx.audit.accessed")
        .target_ref(target_event_id)
        .body(json!({
            "target_ref": target_event_id,
            "actor_id": actor,
            "purpose": format!("e2ee_read;reader_device={device_id}"),
            "accessed_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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
    OperationBuilder::new(space_id, actor, "cx.audit.ryw_receipt")
        .target_ref(source_event_id)
        .body(json!({
            "target_ref": source_event_id,
            "actor_id": actor,
            "purpose": purpose,
            "accessed_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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
        assert_eq!(op.kind, "cx.audit.accessed");
        assert_eq!(op.payload["target_ref"], "cx:event:abc");
        assert_eq!(op.payload["actor_id"], "did:web:alice");
        assert!(
            op.payload["purpose"]
                .as_str()
                .is_some_and(|p| p.contains("reader_device=did:key:zDevice"))
        );
        assert!(op.payload["accessed_at"].is_string());
        // No illegal top-level fields under the strict audit_payload schema.
        assert!(op.payload.get("reader_device").is_none());
        assert!(op.payload.get("target_event_id").is_none());
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
        assert_eq!(op.kind, "cx.audit.ryw_receipt");
        assert_eq!(op.payload["target_ref"], "cx:event:abc");
        assert_eq!(op.payload["actor_id"], "did:web:alice");
        assert!(
            op.payload["purpose"]
                .as_str()
                .is_some_and(|p| p.contains("did:key:zA") && p.contains("did:key:zB"))
        );
        assert!(op.payload["accessed_at"].is_string());
        // No illegal top-level fields under the strict audit_payload schema.
        assert!(op.payload.get("delivered_to_devices").is_none());
        assert!(op.payload.get("source_event_id").is_none());
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
        assert_eq!(op.kind, "cx.identity.presentation_request");
        assert_eq!(op.payload["requested_claims"][0], "display_name");
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
        assert_eq!(op.kind, "cx.identity.disclosure_receipt");
        assert_eq!(op.payload["counterparty"], "did:web:bob");
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
