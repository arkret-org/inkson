//! Durable outgoing-Event helpers for the self client: outgoing-payload schema
//! validation and the events-batch acceptance gate.
//!
//! The `ak.typing` / `ak.receipt.read` / `ak.presence` / `ak.call.signal`
//! plaintext broadcast envelopes used to live here. v1 deleted that rail: the
//! successor is the encrypted-only Signal Extension in [`crate::signal`].

use serde::Serialize;

/// A batch the server did not fully accept.
///
/// The message quotes wire vocabulary — the `status` token and each row's
/// `reason_code` exactly as they arrived — so a pasted log line can be grepped
/// against the server's own response. Control flow never reads it; that is what
/// [`events_submit_rejected_for_reason`] is for.
#[derive(Debug, thiserror::Error)]
struct EventsSubmitRejectedError {
    status: arkret_sdk::EventsSubmitStatus,
    rejected: Vec<arkret_sdk::EventsSubmitRejectedRow>,
}

impl std::fmt::Display for EventsSubmitRejectedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "events submit was not fully accepted: status={}",
            self.status.as_str()
        )?;
        for row in &self.rejected {
            write!(
                formatter,
                "; rejected {} reason_code={}",
                row.id,
                row.reason_code.as_str()
            )?;
            if let Some(detail) = &row.detail {
                write!(formatter, " detail={detail}")?;
            }
        }
        Ok(())
    }
}

/// Match a reducer refusal from the typed per-Event rejection rows. Diagnostic
/// prose is deliberately ignored: changing a message must never change client
/// control flow.
pub(crate) fn events_submit_rejected_for_reason(
    error: &anyhow::Error,
    reason: &arkret_sdk::ReasonCode,
) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<EventsSubmitRejectedError>()
            .is_some_and(|rejection| {
                rejection
                    .rejected
                    .iter()
                    .any(|row| &row.reason_code == reason)
            })
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

pub(crate) fn ensure_events_submit_accepted(
    response: &arkret_sdk::EventsSubmitOutcome,
) -> anyhow::Result<()> {
    if response.rejections.is_empty()
        && matches!(
            response.status,
            arkret_sdk::EventsSubmitStatus::Accepted | arkret_sdk::EventsSubmitStatus::Duplicate
        )
    {
        return Ok(());
    }

    Err(EventsSubmitRejectedError {
        status: response.status,
        rejected: response.rejections.clone(),
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::{EventsSubmitRejectedError, events_submit_rejected_for_reason};

    #[test]
    fn reducer_control_flow_reads_typed_reason_and_ignores_diagnostic_prose() {
        let reason = arkret_sdk::ReasonCode::DependencyMissing;
        let typed = anyhow::Error::new(EventsSubmitRejectedError {
            status: arkret_sdk::EventsSubmitStatus::Partial,
            rejected: vec![arkret_sdk::EventsSubmitRejectedRow {
                index: Some(0),
                id: "ak:event:test".to_owned(),
                reason_code: reason.clone(),
                detail: Some("arbitrary diagnostic".to_owned()),
                missing_event_ids: Vec::new(),
                missing_seal_refs: Vec::new(),
                missing_event_digests: Vec::new(),
            }],
        });
        assert!(events_submit_rejected_for_reason(&typed, &reason));

        let prose_only = anyhow::anyhow!("dependency_missing");
        assert!(!events_submit_rejected_for_reason(&prose_only, &reason));
    }
}
