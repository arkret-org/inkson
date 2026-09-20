//! Durable outgoing-Event helpers for the self client: outgoing-payload schema
//! validation and the authority-submit acceptance gate.
//!
//! The `ak.typing` / `ak.receipt.read` / `ak.presence` / `ak.call.signal`
//! plaintext broadcast envelopes used to live here. v1 deleted that rail: the
//! successor is the encrypted-only Signal Extension in [`crate::signal`].

use serde::Serialize;

/// A submission the current governance Station refused.
///
/// The message quotes wire vocabulary — the rejection status and the Station's
/// `reason_code` exactly as they arrived — so a pasted log line can be grepped
/// against the server's own response. Control flow never reads the prose; that
/// is what [`authority_rejected_for_reason`] is for.
#[derive(Debug, thiserror::Error)]
#[error(
    "authority refused the submission: status={status:?} reason_code={reason_code}",
    status = self.status,
    reason_code = self.reason_code
)]
struct AuthorityRejectedError {
    status: arkret_wire::AuthorityRejectionStatus,
    reason_code: String,
}

/// Match a Station refusal by its exact reason code. Diagnostic prose is
/// deliberately ignored: changing a message must never change client control
/// flow.
pub(crate) fn authority_rejected_for_reason(error: &anyhow::Error, reason: &str) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<AuthorityRejectedError>()
            .is_some_and(|rejection| rejection.reason_code == reason)
    })
}

pub(crate) fn validate_outgoing_registered_event_payload<T: Serialize>(
    kind: &str,
    payload: &T,
) -> anyhow::Result<()> {
    let payload = serde_json::to_value(payload)?;
    arkret_sdk::validate_event_payload(&arkret_sdk::EventKind::from(kind), &payload).map_err(
        |err| {
            anyhow::anyhow!(
                "outgoing event kind '{kind}' payload violates its typed contract: {err}"
            )
        },
    )
}

/// Turn one authority submit outcome into the accepted commit, or into the
/// typed refusal above.
pub(crate) fn ensure_authority_accepted(
    outcome: arkret_wire::AuthoritySubmitOutcome,
) -> anyhow::Result<arkret_wire::RealmCommit> {
    match outcome {
        arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. } => Ok(commit),
        arkret_wire::AuthoritySubmitOutcome::Rejected {
            status,
            reason_code,
        } => Err(AuthorityRejectedError {
            status,
            reason_code,
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorityRejectedError, authority_rejected_for_reason};

    #[test]
    fn control_flow_reads_the_typed_reason_and_ignores_diagnostic_prose() {
        let typed = anyhow::Error::new(AuthorityRejectedError {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            reason_code: "dependency_missing".to_owned(),
        });
        assert!(authority_rejected_for_reason(&typed, "dependency_missing"));
        assert!(!authority_rejected_for_reason(&typed, "policy_violation"));

        let prose_only = anyhow::anyhow!("dependency_missing");
        assert!(!authority_rejected_for_reason(
            &prose_only,
            "dependency_missing"
        ));
    }
}
