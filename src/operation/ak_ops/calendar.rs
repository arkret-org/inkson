//! Calendar Strand profile builders.

use super::{OperationBuilder, strand_id_value};

/// Builds an `ak.rsvp.set` operation carrying the complete RSVP entry.
///
/// The payload is produced by the shared SDK authoring type, never assembled
/// here: the entry is the lattice value, so basis and response have to travel
/// together and stay canonical. The cell effect is derived from the registry in
/// [`OperationBuilder::build_sdk_event`].
///
/// `schedule_basis_refs` is the schedule revision frontier the responder
/// actually observed; it is mirrored into `causal_refs` because a receiver
/// admits the basis only as a subset of the envelope causal edges.
pub fn rsvp_set(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    status: &str,
    occurrence: Option<&str>,
    schedule_basis_refs: Vec<arkret_sdk::Hash>,
    calendar: &arkret_sdk::CalendarEventFields,
    schedule: &arkret_sdk::CalendarScheduleProjection,
) -> anyhow::Result<OperationBuilder> {
    let authoring = arkret_sdk::RsvpAuthoring {
        event_ref: strand_id_value(strand_id)?,
        occurrence: occurrence
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        schedule_basis_refs: schedule_basis_refs.clone(),
        response: arkret_sdk::RsvpResponseBranch::Plaintext(arkret_sdk::RsvpResponse {
            status: rsvp_status_value(status)?,
            comment: None,
        }),
    };
    let payload = authoring
        .into_payload(calendar, schedule)
        .map_err(|err| anyhow::anyhow!("ak.rsvp.set payload is not valid: {err}"))?;
    let payload = serde_json::to_value(payload)
        .map_err(|err| anyhow::anyhow!("ak.rsvp.set payload serialize: {err}"))?;
    arkret_sdk::schema::event_payload_validator_catalog()
        .map_err(|err| anyhow::anyhow!("ak.rsvp.set payload validator catalog: {err}"))?
        .validate_payload("ak.rsvp.set", &payload)
        .map_err(|err| anyhow::anyhow!("ak.rsvp.set payload is not schema-valid: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::RsvpSet,
    )
    .target_ref(strand_id)
    .causal_refs(schedule_basis_refs)
    .body(payload))
}

fn rsvp_status_value(status: &str) -> anyhow::Result<arkret_sdk::RsvpStatus> {
    match status.trim().to_ascii_lowercase().as_str() {
        "accepted" => Ok(arkret_sdk::RsvpStatus::Accepted),
        "declined" => Ok(arkret_sdk::RsvpStatus::Declined),
        "tentative" => Ok(arkret_sdk::RsvpStatus::Tentative),
        other => Err(anyhow::anyhow!(
            "unknown RSVP status {other:?}; expected accepted, declined, or tentative"
        )),
    }
}
