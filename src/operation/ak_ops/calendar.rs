//! Calendar Strand profile builders.

use serde_json::Value;

use super::{OperationBuilder, strand_id_value};

pub fn rsvp_set(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    status: &str,
    occurrence: Option<&str>,
    comment: Option<Value>,
) -> anyhow::Result<OperationBuilder> {
    let comment = comment
        .map(serde_json::from_value::<arkret_sdk::RsvpComment>)
        .transpose()?;
    let payload = arkret_sdk::RsvpSetPayload {
        event_ref: strand_id_value(strand_id)?,
        status: rsvp_status_value(status)?,
        occurrence: occurrence
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        comment,
    };
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
