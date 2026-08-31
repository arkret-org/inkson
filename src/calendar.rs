//! Headless Calendar authoring used by the UI and joint conformance tests.
//!
//! Keeping this entry point outside the Dioxus view tree ensures that the
//! product and the live Inkson + Soland row exercise exactly the same RSVP
//! authoring path.

/// Derives the canonical schedule revision frontier from the accepted Realm
/// event log. The UI calls the same reducer before it authors an RSVP.
pub fn schedule_revision_heads(
    events: &[arkret_sdk::Event],
    strand_id: &str,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<Vec<arkret_sdk::Hash>> {
    crate::views::kanban::calendar_schedule_revision_heads(events, strand_id, digest_suite)
}

#[allow(clippy::too_many_arguments)]
pub fn build_calendar_rsvp_event(
    realm_id: &str,
    actor_id: &arkret_sdk::ActorId,
    strand_id: &str,
    status: &str,
    occurrence: Option<&str>,
    calendar_fields: &arkret_sdk::CalendarEventFields,
    schedule_basis_refs: Vec<arkret_sdk::Hash>,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let schedule_bytes = arkret_sdk::canonical::canonical_json_bytes(calendar_fields)?;
    let schedule = if schedule_basis_refs.len() == 1 {
        arkret_sdk::CalendarScheduleProjection::from_heads(&[(
            schedule_basis_refs[0].clone(),
            Some(schedule_bytes),
        )])
    } else {
        arkret_sdk::CalendarScheduleProjection::from_heads(
            &schedule_basis_refs
                .iter()
                .cloned()
                .map(|head| (head, None))
                .collect::<Vec<_>>(),
        )
    };
    let mut authoring = crate::operation::ak_ops::rsvp_authoring(strand_id, status, occurrence)?;
    authoring.schedule_basis_refs = schedule_basis_refs.clone();
    Ok(crate::operation::LocalOperation::new(
        arkret_sdk::calendar::build_rsvp_set_intent(
            authoring,
            calendar_fields,
            &schedule,
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
            },
            actor_id.clone(),
            crate::clock::now_utc_millis(),
            schedule_basis_refs,
        )?,
    ))
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
                vec![arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap()],
            )
            .unwrap();
            assert_eq!(operation.actor_id(), &actor);
        }
    }
}
