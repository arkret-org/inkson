//! Scheduling only: a completed no-work pass grants no read, key or write
//! capability. Any changed input must run the native original path again.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use arkret_sdk::http_client::own_station_results::OwnStationSessionSnapshot;

use super::*;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Input {
    session: OwnStationSessionSnapshot,
    device: (crate::secure_key_store::ActiveDeviceSeedScope, u64),
    visibility: crate::state::RealmListReadFence,
    key_revision: u64,
    digest: [u8; 32],
}

impl Input {
    pub(super) fn capture(
        source: &OwnStationStateClient,
        state: &StateStoreHandle,
        snapshot: &crate::realm_events_engine::CreatorOwnSnapshot,
        originals: &[Event],
    ) -> anyhow::Result<Self> {
        let active = require_reader(source, state)?;
        let device = crate::secure_key_store::active_device_seed_scope_snapshot()
            .ok_or_else(|| anyhow::anyhow!("history reader Device ended"))?;
        anyhow::ensure!(device.0 == active, "history reader Device changed");
        let current = snapshot.value()?;
        anyhow::ensure!(
            snapshot.session() == source.session()?,
            "history current belongs to another session"
        );
        // Snapshot timestamps/signatures can change at an unchanged cut.
        // Keep every semantic current/floor input, not just a head number.
        let bytes = arkret_sdk::canonical::canonical_json_bytes(&(
            &current.realm_id,
            current.governance_generation,
            &current.purpose,
            &current.history_basis,
            &current.visible_stream_heads,
            &current.current_state_entries,
            &current.retention_and_history_floor,
            originals,
        ))?;
        let (visibility, key_revision) = state.read(|store| {
            (
                store.realm_list_read_fence(current.realm_id.as_str()),
                store.historical_content_rosters.content_key_revision(),
            )
        });
        Ok(Self {
            session: source.session()?.clone(),
            device,
            visibility,
            key_revision,
            digest: arkret_sdk::canonical::sha256_bytes(bytes),
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct IdleReconciliations(Arc<Mutex<BTreeMap<RealmId, Input>>>);

impl IdleReconciliations {
    pub(super) fn begin(&self, realm: &RealmId, input: &Input, no_controls: bool) -> bool {
        let Ok(mut entries) = self.0.lock() else {
            return false;
        };
        let previous = entries.remove(realm);
        if no_controls && previous.as_ref() == Some(input) {
            entries.insert(realm.clone(), previous.unwrap());
            true
        } else {
            false
        }
    }

    pub(super) fn finish(&self, realm: &RealmId, input: Input) {
        if let Ok(mut entries) = self.0.lock() {
            // Bounded process-local scheduling state. Eviction only adds work.
            if entries.len() >= 64 {
                entries.pop_first();
            }
            entries.insert(realm.clone(), input);
        }
    }

    pub(crate) fn clear(&self) {
        if let Ok(mut entries) = self.0.lock() {
            entries.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        let account = arkret_test_kit::subjects::alice_account_id();
        let session = OwnStationSessionSnapshot::new(
            arkret_sdk::StationConnectionBinding {
                service_id: account.station_id.clone(),
                base_url: "http://127.0.0.1:12345/".into(),
                trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example")
                    .unwrap(),
                authentication_metadata: arkret_sdk::AuthenticationMetadata::minimal(),
            },
            account.clone(),
            account.station_id.clone(),
            arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
            0,
            "test-grant".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
        Input {
            session,
            device: (
                crate::secure_key_store::ActiveDeviceSeedScope {
                    authority: account,
                    device_id: arkret_test_kit::subjects::alice_device_id(),
                },
                0,
            ),
            visibility: Default::default(),
            key_revision: 0,
            digest: [1; 32],
        }
    }

    #[test]
    fn only_a_completed_idle_pass_suppresses_twenty_identical_wakeups() {
        let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [9; 32],
        ));
        let idle = IdleReconciliations::default();
        let original = input();
        assert!(!idle.begin(&realm, &original, true));
        // Failed or still-missing passes never call finish and must retry.
        assert!(!idle.begin(&realm, &original, true));
        idle.finish(&realm, original.clone());
        for _ in 0..20 {
            assert!(idle.begin(&realm, &original, true));
        }
        // A delayed control is work even at a previously completed cut.
        assert!(!idle.begin(&realm, &original, false));
        assert!(!idle.begin(&realm, &original, true));
    }

    #[test]
    fn native_context_and_local_custody_changes_reenter_the_original_path() {
        let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [9; 32],
        ));
        let original = input();
        let mut changes = Vec::new();
        let mut changed = original.clone();
        changed.digest[0] ^= 1;
        changes.push(changed);
        let mut changed = original.clone();
        changed.device.1 += 1;
        changes.push(changed);
        let mut changed = original.clone();
        changed.key_revision += 1;
        changes.push(changed);
        let mut changed = original.clone();
        changed.visibility = crate::state::RealmListReadFence::after_removal_for_test(1);
        changes.push(changed);
        let mut changed = original.clone();
        changed.session = changed.session.with_provider_identity(Default::default());
        changes.push(changed);
        for changed in changes {
            let idle = IdleReconciliations::default();
            idle.finish(&realm, original.clone());
            assert!(!idle.begin(&realm, &changed, true));
            assert!(!idle.begin(&realm, &original, true));
        }
        let idle = IdleReconciliations::default();
        idle.finish(&realm, original.clone());
        idle.clone().clear();
        assert!(!idle.begin(&realm, &original, true));
    }
}
