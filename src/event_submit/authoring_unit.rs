//! Cross-Event shape rules for one atomic authoring unit.
//!
//! A producer Event carries no chain position and no predecessor, so a unit is
//! no longer a chain: it is just an ordered list whose later members name
//! earlier members by their final `event_id`. What remains worth checking is
//! the registered shape of the founding units, which the current governance
//! Station admits as a whole.

use super::EventIntent;
#[cfg(test)]
use super::EventUnitStep;

/// The one authoring fact a unit determines for itself.
///
/// A Realm genesis derives its own Realm id from the create Event, so every
/// Event in that unit is authored under the digest suite the genesis id
/// carries rather than under a suite read from an existing Realm id.
#[derive(Default)]
pub(super) struct UnitAuthoringChain {
    genesis: bool,
}

impl UnitAuthoringChain {
    /// Take from `intent` whatever the unit has to know before it is authored.
    ///
    /// Only a unit's first member can open a Realm, so `first` is what
    /// separates this unit's genesis from an ordinary nested `ak.realm.create`.
    pub(super) fn observe(&mut self, intent: &EventIntent, first: bool) {
        if first && intent.kind() == &arkret_sdk::EventKind::RealmCreate {
            self.genesis = true;
        }
    }

    pub(super) fn is_genesis_unit(&self) -> bool {
        self.genesis
    }
}

/// Re-run the cross-Event unit shapes on the authored result.
///
/// These validators exist because a founding unit is admitted as a whole: they
/// check the relationships between members, which only hold once every member
/// carries its final identity.
pub(super) fn validate_authored_unit_shape(
    authored: &[arkret_sdk::AuthoredEvent],
) -> anyhow::Result<()> {
    if authored
        .first()
        .is_none_or(|event| event.kind != arkret_sdk::EventKind::RealmCreate)
    {
        return Ok(());
    }
    let events = authored
        .iter()
        .map(arkret_sdk::AuthoredEvent::event)
        .cloned()
        .collect::<Vec<_>>();
    if events.len() == 2 && events[1].kind == arkret_sdk::EventKind::DeviceAuthorize {
        arkret_wire::PcrGenesisUnit::new(events[0].clone(), events[1].clone())
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("prepared self-principal PCR unit: {error}"))?;
        return Ok(());
    }
    if events.len() == 1 && crate::pcr_authority::is_agent_pcr_genesis(&events[0]) {
        return Ok(());
    }
    arkret_policy::realm_bootstrap::validate_realm_genesis_event(&events[0])
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("realm genesis unit: {error}"))
}

/// Run an authoring unit without a transport, for a unit test.
///
/// Drives the same ordering contract production drives — step `n` sees the
/// final identities of everything steps `0..n` authored — so a test exercises
/// it rather than restating it. Test-only: the pinned authoring timestamps are
/// the one input a test cannot obtain from the environment.
#[cfg(test)]
pub(crate) fn author_event_unit_for_test(
    steps: Vec<EventUnitStep>,
) -> anyhow::Result<Vec<arkret_sdk::AuthoredEvent>> {
    let mut authored: Vec<arkret_sdk::AuthoredEvent> = Vec::with_capacity(steps.len());
    for step in steps {
        for intent in step(&authored)? {
            let nth = u64::try_from(authored.len()).unwrap_or(0).saturating_add(1);
            let event = intent
                .with_created_at(crate::operation::test_authoring_created_at_at_seq(nth))
                .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .map_err(|error| anyhow::anyhow!("author unit Event: {error}"))?;
            authored.push(event);
        }
    }
    Ok(authored)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn realm_intent() -> EventIntent {
        let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        serde_json::from_value(json!({
            "kind": "ak.message.send",
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            },
            "actor_id": actor_id,
            "created_at": "2026-05-19T00:00:00.000Z",
            "payload": {}
        }))
        .unwrap()
    }

    #[test]
    fn a_later_member_sees_the_final_identity_of_an_earlier_one() {
        let first = realm_intent();
        let steps: Vec<EventUnitStep> = vec![
            Box::new(move |_| Ok(vec![first])),
            Box::new(move |authored| {
                let previous = authored
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("the first member must already be authored"))?;
                Ok(vec![realm_intent().with_ref(arkret_sdk::EventRef::new(
                    previous.event_id().to_string(),
                    "predecessor",
                ))])
            }),
        ];

        let authored = author_event_unit_for_test(steps).unwrap();

        assert_eq!(authored.len(), 2);
        assert_eq!(
            authored[1].refs[0].event_id.as_str(),
            authored[0].event_id().as_str()
        );
        assert_ne!(authored[0].event_id(), authored[1].event_id());
    }

    #[test]
    fn a_non_founding_unit_has_no_registered_shape_to_check() {
        let authored =
            author_event_unit_for_test(vec![Box::new(|_| Ok(vec![realm_intent()]))]).unwrap();

        assert!(validate_authored_unit_shape(&authored).is_ok());
    }
}
