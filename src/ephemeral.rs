//! Durable outgoing-Event helpers for the self client: outgoing-payload schema
//! validation and the events-batch acceptance gate.
//!
//! The `ak.typing` / `ak.receipt.read` / `ak.presence` / `ak.call.signal`
//! plaintext broadcast envelopes used to live here. v1 deleted that rail: the
//! successor is the encrypted-only Signal Extension in [`crate::signal`].

use serde::Serialize;

#[derive(Debug, thiserror::Error)]
#[error("events submit was not fully accepted: status={status:?}, rejected={rejected:?}")]
struct EventsSubmitRejectedError {
    status: arkret_sdk::EventsSubmitStatus,
    rejected: Vec<arkret_sdk::EventsSubmitRejectedRow>,
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
    let catalog = arkret_sdk::schema::event_payload_validator_catalog()?;
    if !catalog
        .missing_payload_validators_for(std::iter::once(kind))
        .is_empty()
    {
        return Ok(());
    }

    catalog.validate_payload(kind, &payload).map_err(|err| {
        anyhow::anyhow!(
            "outgoing event kind '{kind}' payload violates registered payload schema: {err}"
        )
    })
}

pub(crate) fn ensure_events_submit_accepted(
    response: &arkret_sdk::EventsSubmitOutcome,
) -> anyhow::Result<()> {
    if response.rejected.is_empty()
        && matches!(
            response.status,
            arkret_sdk::EventsSubmitStatus::Accepted | arkret_sdk::EventsSubmitStatus::Duplicate
        )
    {
        return Ok(());
    }

    Err(EventsSubmitRejectedError {
        status: response.status,
        rejected: response.rejected.clone(),
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
