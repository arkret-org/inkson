use std::collections::BTreeMap;

use super::EventIntent;
#[cfg(test)]
use super::EventUnitStep;

/// The actor chain a single authoring unit builds as it goes.
///
/// A unit's members share one `(realm_id, actor_id)` chain, so member `n+1` takes
/// its position from what member `n` actually authored rather than from a remote
/// frontier that cannot yet see it. Genesis is what forces this to be one type: a
/// registered genesis unit CREATES its chain, so a remote lookup cannot tell
/// genesis apart from an invisible Realm and must not be consulted at all.
#[derive(Default)]
pub(super) struct UnitAuthoringChain {
    frontiers: BTreeMap<(arkret_sdk::RealmId, arkret_sdk::ActorId), (u64, arkret_sdk::EventId)>,
    genesis_digest_suite: Option<arkret_sdk::canonical::DigestSuite>,
}

impl UnitAuthoringChain {
    /// Take from `intent` whatever the chain has to know before it is authored.
    ///
    /// Only a unit's first member can open a Realm, so `first` is what separates
    /// this unit's genesis from an ordinary nested `ak.realm.create`.
    pub(super) fn observe(&mut self, intent: &EventIntent, first: bool) -> anyhow::Result<()> {
        if !(first && intent.kind() == &arkret_sdk::EventKind::RealmCreate) {
            return Ok(());
        }
        self.genesis_digest_suite = Some(
            serde_json::from_value::<arkret_sdk::RealmCreatePayload>(serde_json::to_value(
                intent.payload(),
            )?)
            .map_err(|error| anyhow::anyhow!("decode Realm genesis digest suite: {error}"))?
            .object
            .digest_algorithm,
        );
        Ok(())
    }

    /// This unit's genesis digest suite, if it authors a Realm into existence.
    pub(super) fn genesis_digest_suite(&self) -> Option<arkret_sdk::canonical::DigestSuite> {
        self.genesis_digest_suite
    }

    pub(super) fn is_genesis_unit(&self) -> bool {
        self.genesis_digest_suite.is_some()
    }

    /// The chain position this unit already determines on its own, or `None` when
    /// the caller has to resolve it against the accepted actor frontier.
    pub(super) fn basis_within_unit(
        &self,
        intent: &EventIntent,
    ) -> anyhow::Result<Option<(u64, Vec<arkret_sdk::EventId>)>> {
        let scope = intent
            .realm_id_opt()
            .cloned()
            .map(|realm_id| (realm_id, intent.actor_id().clone()));
        match scope.as_ref().and_then(|scope| self.frontiers.get(scope)) {
            Some((actor_seq, event_id)) => {
                let next_actor_seq = actor_seq
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("actor sequence exhausted for batch scope"))?;
                Ok(Some((next_actor_seq, vec![event_id.clone()])))
            }
            None if self.is_genesis_unit() => Ok(Some((0, Vec::new()))),
            None => Ok(None),
        }
    }

    /// Advance the chain past a member this unit just authored.
    pub(super) fn record(&mut self, event: &arkret_sdk::AuthoredEvent) {
        self.frontiers.insert(
            (event.realm_id.clone(), event.actor_id.clone()),
            (event.actor_seq, event.event_id().clone()),
        );
    }
}

/// Re-run the cross-Event unit shapes on the authored result.
///
/// These validators exist because a unit is admitted atomically: they check
/// the relationships between members, which only hold once every member
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
    let refs = events.iter().collect::<Vec<_>>();
    if events.len() == 2 && events[1].kind == arkret_sdk::EventKind::DeviceAuthorize {
        return arkret_bootstrap::validate_self_principal_pcr_genesis_unit(
            &events[0],
            &events[1],
            &|event| crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256),
        )
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("prepared self-principal PCR unit: {error}"));
    }
    if events.len() == 1
        && arkret_bootstrap::materialize_agent_pcr_control(&events, &|event| {
            crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256)
        })
        .is_ok()
    {
        return Ok(());
    }
    if events.len() == 4
        && let Ok(exact) = <[&arkret_sdk::Event; 4]>::try_from(refs.as_slice())
        && arkret_sdk::DirectConversationFoundingPlan::from_events(exact).is_ok()
    {
        return Ok(());
    }
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!(error.reason_code()))
}

/// Run an authoring unit without a transport, for a unit test.
///
/// Drives the same [`UnitAuthoringChain`] production drives, so the ordering
/// contract — step `n` sees the final identities of everything steps `0..n`
/// authored, and genesis opens its own chain at `actor_seq` 0 under the suite its
/// payload declares — is exercised here rather than restated. Only the two inputs
/// a test cannot obtain are pinned: the accepted actor frontier and the durable
/// signing stamp. Test-only: nothing in production may author against a pinned
/// chain.
#[cfg(test)]
pub(crate) fn author_event_unit_for_test(
    steps: Vec<EventUnitStep>,
) -> anyhow::Result<Vec<arkret_sdk::AuthoredEvent>> {
    let mut authored: Vec<arkret_sdk::AuthoredEvent> = Vec::with_capacity(steps.len());
    let mut chain = UnitAuthoringChain::default();
    for step in steps {
        for intent in step(&authored)? {
            chain.observe(&intent, authored.is_empty())?;
            // The one position the unit cannot determine for itself is its first
            // member's, when that member continues a chain the frontier owns.
            let (actor_seq, prev_refs) =
                chain.basis_within_unit(&intent)?.unwrap_or((1, Vec::new()));
            let intent = intent.with_prev_refs(prev_refs);
            let hlc = crate::operation::test_authoring_hlc_at_seq(actor_seq);
            let event = match chain.genesis_digest_suite() {
                Some(digest_suite) => intent.author_with_digest_suite(actor_seq, hlc, digest_suite),
                None => {
                    intent.author_with_digest_suite(actor_seq, hlc, arkret_sdk::DigestSuite::Sha256)
                }
            }
            .map_err(|error| anyhow::anyhow!("author unit Event: {error}"))?;
            chain.record(&event);
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
    fn same_scope_successor_uses_previous_authored_event_id() {
        let intent = realm_intent();
        let previous_event_id =
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap();
        let mut chain = UnitAuthoringChain::default();
        chain.frontiers.insert(
            (
                intent.realm_id_opt().unwrap().clone(),
                intent.actor_id().clone(),
            ),
            (7, previous_event_id.clone()),
        );

        let (actor_seq, prev_refs) = chain.basis_within_unit(&intent).unwrap().unwrap();

        assert_eq!(actor_seq, 8);
        assert_eq!(prev_refs, vec![previous_event_id]);
    }

    #[test]
    fn genesis_starts_at_zero_without_predecessors() {
        let intent = realm_intent();
        let chain = UnitAuthoringChain {
            genesis_digest_suite: Some(arkret_sdk::DigestSuite::Sha256),
            ..Default::default()
        };

        let (actor_seq, prev_refs) = chain.basis_within_unit(&intent).unwrap().unwrap();

        assert_eq!(actor_seq, 0);
        assert!(prev_refs.is_empty());
    }
}
