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

/// Author an RSVP only after the installed, verified Strand current and MLS
/// current identify the same effective Realm scope.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_encrypted_calendar_rsvp_event(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &arkret_sdk::ActorId,
    device_id: &arkret_sdk::DeviceId,
    strand_id: &str,
    status: &str,
    occurrence: Option<&str>,
    calendar_fields: &arkret_sdk::CalendarEventFields,
    schedule_basis_event: arkret_sdk::EventId,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let strand = arkret_sdk::StrandId::new(strand_id.to_owned())?;
    let current = state_store.current_product_view().ok_or_else(|| {
        anyhow::anyhow!("verified Strand current is unavailable for RSVP authoring")
    })?;
    anyhow::ensure!(
        current.realm_id == realm_id,
        "RSVP Realm current does not match the target"
    );
    let strand_value = current
        .entries
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentResult::Value {
                selector:
                    arkret_wire::CurrentSelector::Strand {
                        strand_id: selected,
                    },
                value,
                ..
            } if selected == &strand => Some(value),
            _ => None,
        })
        .ok_or_else(|| {
            anyhow::anyhow!("verified Strand current is unavailable for RSVP authoring")
        })?;
    let current_strand: arkret_models_collaboration::objects::strand::Strand =
        serde_json::from_value(strand_value.clone())?;
    anyhow::ensure!(
        current_strand.id.as_ref() == Some(&strand)
            && current_strand.realm_id == realm
            && current_strand.scope_circle_id.is_none(),
        "RSVP target has no verified Realm effective scope"
    );
    let scope = arkret_sdk::ScopeRef::Realm { realm_id: realm };
    let arkret_sdk::ActorId::Account {
        account_id: authority,
    } = actor_id
    else {
        anyhow::bail!("RSVP MLS author must be an account actor");
    };
    let active = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("active RSVP signing identity is unavailable"))?;
    anyhow::ensure!(
        active.authority == *authority && active.device_id == *device_id,
        "RSVP MLS author does not match the active device"
    );
    anyhow::ensure!(
        matches!(
            state_store.installed_scope_mls_current(&scope),
            crate::current_projection::ScopeMlsCurrent::Activated(_)
        ),
        "RSVP effective scope MLS activation is not verified"
    );
    let snapshot = state_store
        .mls_checkpoint_for_scope(&scope)
        .ok_or_else(|| anyhow::anyhow!("RSVP MLS checkpoint is unavailable"))?;
    let accepted_group_state_ref = state_store
        .mls_group_state_ref_for_scope(&scope, &snapshot.group_id, snapshot.epoch)
        .map_err(|_| anyhow::anyhow!("RSVP MLS group-state Event is not accepted"))?;
    let mut authoring = crate::operation::ak_ops::rsvp_authoring(strand_id, status, occurrence)?;
    authoring.schedule_basis_refs = vec![schedule_basis_event.clone()];
    let schedule_bytes = arkret_sdk::canonical::canonical_json_bytes(calendar_fields)?;
    let schedule = arkret_sdk::CalendarScheduleProjection::from_winner(
        schedule_basis_event.event_digest(),
        Some(schedule_bytes),
    );
    let mut payload = authoring
        .clone()
        .into_payload(calendar_fields, &schedule)
        .map_err(|error| anyhow::anyhow!("RSVP payload is not authorable: {error}"))?;
    let arkret_sdk::RsvpResponseBranch::Plaintext(response) = &authoring.response else {
        anyhow::bail!("RSVP status did not produce a response");
    };
    let response_bytes = arkret_sdk::canonical::canonical_json_bytes(response)?;
    let (_, encrypted) =
        crate::mls::runtime::encrypt_values_with_device_snapshot_for_effective_scope(
            state_store,
            secure_store,
            realm_id,
            authority,
            device_id,
            arkret_models_collaboration::objects::productivity::RSVP_RESPONSE_CONTENT_TYPE,
            &[response_bytes],
            arkret_wire::event_kind_str::RSVP_SET,
            accepted_group_state_ref,
            None,
            None,
        )
        .map_err(|error| {
            anyhow::anyhow!("cannot encrypt RSVP response: {}", error.user_message())
        })?;
    let [encrypted] = <[_; 1]>::try_from(encrypted)
        .map_err(|_| anyhow::anyhow!("MLS returned an unexpected RSVP ciphertext count"))?;
    let payload_ciphertext: arkret_sdk::EncryptedPayload = serde_json::from_value(encrypted)?;
    let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(&payload_ciphertext)?;
    payload.entry.response = None;
    payload.entry.encrypted_response = Some(Box::new(envelope));
    payload.validate()?;
    let intent = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::RsvpSet>::new(
        scope,
        actor_id.clone(),
        payload,
    )?
    .into_intent(crate::clock::now_utc_millis())?;
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
