//! Headless Calendar authoring used by the UI and joint conformance tests.
//!
//! Keeping this entry point outside the Dioxus view tree ensures that the
//! product and the live Inkson + Soland row exercise exactly the same RSVP
//! authoring path.

/// Derive the deterministic schedule revision winner from one Strand's own
/// committed stream page.
///
/// The winner is returned as its exact committed reference so the caller can
/// verify admission before authoring. The RSVP payload names the EventId.
pub fn schedule_revision_winner(
    commits: &[arkret_wire::CommittedEventFullView],
    strand_id: &str,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<arkret_wire::CommittedEventRef> {
    let events: Vec<arkret_sdk::Event> = commits.iter().map(|item| item.event.clone()).collect();
    let winner =
        crate::views::kanban::calendar_schedule_revision_winner(&events, strand_id, digest_suite)?;
    commits
        .iter()
        .find(|item| item.event.event_id.event_digest() == winner.as_str())
        .map(|item| arkret_wire::CommittedEventRef {
            event_id: item.event.event_id.clone(),
            commit_id: item.commit.commit_id.clone(),
            stream_ref: item.commit.stream_ref.clone(),
            stream_position: item.commit.stream_position,
        })
        .ok_or_else(|| {
            anyhow::anyhow!("the schedule revision winner has no commit in this stream page")
        })
}

/// Author `ak.calendar.rsvp.set` against the deterministic schedule winner.
///
/// `schedule_basis` is the admitted winning schedule revision. The payload
/// names its typed EventId, not the commit envelope or a bare digest.
pub fn build_calendar_rsvp_event(
    realm_id: &str,
    actor_id: &arkret_sdk::ActorId,
    strand_id: &str,
    status: &str,
    occurrence: Option<&str>,
    calendar_fields: &arkret_sdk::CalendarEventFields,
    schedule_basis: arkret_wire::CommittedEventRef,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let schedule_bytes = arkret_sdk::canonical::canonical_json_bytes(calendar_fields)?;
    let schedule = arkret_sdk::CalendarScheduleProjection::from_winner(
        schedule_basis.event_id.event_digest(),
        Some(schedule_bytes),
    );
    let mut authoring = crate::operation::ak_ops::rsvp_authoring(strand_id, status, occurrence)?;
    authoring.schedule_basis_refs = vec![schedule_basis.event_id];
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
                arkret_wire::CommittedEventRef {
                    event_id: arkret_sdk::EventId::new(
                        "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    )
                    .unwrap(),
                    commit_id: arkret_sdk::RealmCommitId::new(
                        "ak:realm_commit:0196419b-0000-7000-8000-000000000001",
                    )
                    .unwrap(),
                    stream_ref: arkret_wire::CommitStreamRef::Realm {
                        realm_id: arkret_sdk::RealmId::new(
                            "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
                        )
                        .unwrap(),
                    },
                    stream_position: 3,
                },
            )
            .unwrap();
            assert_eq!(operation.actor_id(), &actor);
        }
    }
}
