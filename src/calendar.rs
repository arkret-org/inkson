//! Headless Calendar authoring used by the UI and joint conformance tests.
//!
//! Keeping this entry point outside the Dioxus view tree ensures that the
//! product and the live Inkson + Soland row exercise exactly the same RSVP
//! authoring path.

/// Author `ak.calendar.rsvp.set` against the deterministic schedule winner.
///
/// `schedule_basis_event` is the typed Event identity published by the current
/// Strand projection. The governing Station has already selected that value;
/// this client does not replay Event history to choose a winner.
pub fn build_calendar_rsvp_event(
    realm_id: &str,
    actor_id: &arkret_sdk::ActorId,
    strand_id: &str,
    status: &str,
    occurrence: Option<&str>,
    calendar_fields: &arkret_sdk::CalendarEventFields,
    schedule_basis_event: arkret_sdk::EventId,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let schedule_bytes = arkret_sdk::canonical::canonical_json_bytes(calendar_fields)?;
    let schedule = arkret_sdk::CalendarScheduleProjection::from_winner(
        schedule_basis_event.event_digest(),
        Some(schedule_bytes),
    );
    let mut authoring = crate::operation::ak_ops::rsvp_authoring(strand_id, status, occurrence)?;
    authoring.schedule_basis_refs = vec![schedule_basis_event];
    let payload = authoring
        .into_payload(calendar_fields, &schedule)
        .map_err(|error| anyhow::anyhow!("RSVP payload is not authorable: {error}"))?;
    let intent = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::RsvpSet>::new(
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        },
        actor_id.clone(),
        payload,
    )
    .map_err(|error| anyhow::anyhow!("RSVP draft construction failed: {error}"))?
    .into_intent(crate::clock::now_utc_millis())
    .map_err(|error| anyhow::anyhow!("RSVP intent erasure failed: {error}"))?;
    Ok(crate::operation::LocalOperation::new(intent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsvp_authoring_preserves_explicit_station_without_global_session() {
        let fields: arkret_sdk::CalendarEventFields = serde_json::from_value(serde_json::json!({
            "start": "2026-08-31T09:00:00", "end": "2026-08-31T10:00:00",
            "timezone": "UTC", "tzdb_version": "2025b", "all_day": false,
            "status": "confirmed"
        }))
        .unwrap();
        for station in [
            "ak:did_core:web:station-a.example",
            "ak:did_core:web:station-b.example",
        ] {
            let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_sdk::DidCoreId::new(station).unwrap(),
            ));
            let operation = build_calendar_rsvp_event(
                "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
                &actor,
                "ak:strand:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim",
                "accepted",
                None,
                &fields,
                arkret_sdk::EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(operation.actor_id(), &actor);
        }
    }
}
