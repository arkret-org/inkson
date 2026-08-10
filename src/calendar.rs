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
) -> anyhow::Result<Vec<arkret_sdk::Hash>> {
    crate::views::kanban::calendar_schedule_revision_heads(events, strand_id)
}

#[allow(clippy::too_many_arguments)]
pub fn build_calendar_rsvp_event(
    realm_id: &str,
    actor_id: &str,
    strand_id: &str,
    status: &str,
    occurrence: Option<&str>,
    calendar_fields: &arkret_sdk::CalendarEventFields,
    schedule_basis_refs: Vec<arkret_sdk::Hash>,
    actor_seq: u64,
    hlc: arkret_sdk::Hlc,
) -> anyhow::Result<arkret_sdk::Event> {
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
    Ok(arkret_sdk::calendar::build_rsvp_set_event(
        authoring,
        calendar_fields,
        &schedule,
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        },
        arkret_sdk::ActorId::new(actor_id.to_owned())?,
        actor_seq,
        hlc,
        schedule_basis_refs,
    )?)
}
