//! Calendar Strand profile builders.

pub fn rsvp_authoring(
    strand_id: &str,
    status: &str,
    occurrence: Option<&str>,
) -> anyhow::Result<arkret_sdk::RsvpAuthoring> {
    Ok(arkret_sdk::RsvpAuthoring {
        event_ref: arkret_sdk::StrandId::new(strand_id.trim().to_owned())?,
        occurrence: occurrence.map(str::to_owned),
        schedule_basis_refs: Vec::new(),
        response: arkret_sdk::RsvpResponseBranch::Plaintext(arkret_sdk::RsvpResponse {
            status: rsvp_status_value(status)?,
            comment: None,
        }),
    })
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
