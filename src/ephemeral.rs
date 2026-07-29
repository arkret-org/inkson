//! Durable outgoing-Event helpers for the self client: outgoing-payload schema
//! validation and the events-batch acceptance gate.
//!
//! The `ak.typing` / `ak.receipt.read` / `ak.presence` / `ak.call.signal`
//! plaintext broadcast envelopes used to live here. v1 deleted that rail: the
//! successor is the encrypted-only Signal Extension in [`crate::signal`].

use serde::Serialize;

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

    let details = response
        .rejected
        .iter()
        .map(|item| {
            let id = item.id.as_str();
            let reason = item.reason_code.as_str();
            let detail = item.detail.as_deref().unwrap_or("");
            if detail.is_empty() {
                format!("{id}:{reason}")
            } else {
                format!("{id}:{reason}:{detail}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    let status = match response.status {
        arkret_sdk::EventsSubmitStatus::Accepted => "accepted",
        arkret_sdk::EventsSubmitStatus::Duplicate => "duplicate",
        arkret_sdk::EventsSubmitStatus::Partial => "partial",
        arkret_sdk::EventsSubmitStatus::HistoricalOnly => "historical_only",
    };
    anyhow::bail!("events submit was not fully accepted: status={status}, rejected=[{details}]");
}
