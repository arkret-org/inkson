use super::*;

fn repair_stage_rank(stage: garth::DirectConversationRepairStage) -> u8 {
    match stage {
        garth::DirectConversationRepairStage::AwaitingSelfRejoinAcceptance => 0,
        garth::DirectConversationRepairStage::SelfRejoinAccepted => 1,
        garth::DirectConversationRepairStage::DispatchFrozen => 2,
        garth::DirectConversationRepairStage::DispatchRetryable => 3,
        garth::DirectConversationRepairStage::EnqueueOutcomePendingDurability => 4,
        garth::DirectConversationRepairStage::Enqueued => 5,
        garth::DirectConversationRepairStage::WelcomeDurable => 6,
        garth::DirectConversationRepairStage::Activated => 7,
    }
}

impl LocalStateStore {
    /// Persist the exact Garth-owned repair snapshot. A caller must freeze the
    /// signed dispatch before the first write so `request_id` is the durable
    /// saga identity and retries can only reuse the retained canonical bytes.
    pub(crate) fn save_direct_conversation_repair(
        &mut self,
        planner: &garth::DirectConversationRepairPlanner,
    ) -> anyhow::Result<String> {
        let snapshot = planner.snapshot();
        // Validate every cross-field binding before it can reach disk. Keep
        // the original pending-durability stage; restore_durable deliberately
        // advances that stage only when reading a committed snapshot back.
        garth::DirectConversationRepairPlanner::restore_durable(snapshot.clone())?;
        let request_id = snapshot
            .frozen_dispatch
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("repair dispatch must be frozen before persistence"))?
            .request
            .request_id
            .to_string();
        self.ensure_cached_loaded();
        if let Some(existing) = self.cached.direct_conversation_repairs.get(&request_id)
            && existing != &snapshot
        {
            // Stage progression is allowed, but the immutable frozen request
            // and route must stay byte-identical.
            let existing_frozen = existing.frozen_dispatch.as_ref();
            let next_frozen = snapshot.frozen_dispatch.as_ref();
            if existing.route != snapshot.route
                || existing_frozen.map(|value| &value.canonical_request_bytes)
                    != next_frozen.map(|value| &value.canonical_request_bytes)
                || existing_frozen.map(|value| &value.request_digest)
                    != next_frozen.map(|value| &value.request_digest)
            {
                anyhow::bail!("repair request_id conflicts with persisted canonical dispatch");
            }
            if repair_stage_rank(snapshot.stage) < repair_stage_rank(existing.stage)
                || existing
                    .enqueue_outcome
                    .as_ref()
                    .is_some_and(|outcome| snapshot.enqueue_outcome.as_ref() != Some(outcome))
                || existing
                    .welcome_digest
                    .as_ref()
                    .is_some_and(|digest| snapshot.welcome_digest.as_ref() != Some(digest))
                || existing
                    .activation_event_id
                    .as_ref()
                    .is_some_and(|event_id| snapshot.activation_event_id.as_ref() != Some(event_id))
            {
                anyhow::bail!("repair durable evidence cannot regress or be replaced");
            }
        }
        self.cached
            .direct_conversation_repairs
            .insert(request_id.clone(), snapshot);
        self.flush()?;
        Ok(request_id)
    }

    /// Restore a committed repair. Garth validates tamper evidence and turns
    /// a committed `enqueue_outcome_pending_durability` snapshot into the
    /// restart-safe `enqueued` stage.
    pub(crate) fn direct_conversation_repair(
        &self,
        request_id: &str,
    ) -> anyhow::Result<Option<garth::DirectConversationRepairPlanner>> {
        self.load()
            .direct_conversation_repairs
            .get(request_id)
            .cloned()
            .map(garth::DirectConversationRepairPlanner::restore_durable)
            .transpose()
            .map_err(anyhow::Error::from)
    }

    /// Advance only the repair whose realm and exact requester KeyPackage
    /// match a successfully consumed repair Welcome. Ordinary Welcomes and a
    /// peer-selected substitute KeyPackage cannot unlock activation.
    pub(crate) fn record_consumed_direct_conversation_repair_welcome(
        &mut self,
        realm_id: &str,
        requester_keypackage_ref: &str,
        welcome_digest: arkret_sdk::Hash,
    ) -> anyhow::Result<Option<String>> {
        self.ensure_cached_loaded();
        let mut candidates = Vec::new();
        for (request_id, snapshot) in &self.cached.direct_conversation_repairs {
            if snapshot.route.coordinates.realm_id.as_str() != realm_id
                || snapshot.route.target_keypackage_ref.as_str() != requester_keypackage_ref
            {
                continue;
            }
            // A crash after the enqueue outcome crossed the durable barrier but
            // before the convenience `Enqueued` rewrite leaves the committed
            // snapshot at `EnqueueOutcomePendingDurability`. Restoring is the
            // authority for that boundary; checking the raw enum would strand
            // the exact repair Welcome after restart.
            let planner =
                garth::DirectConversationRepairPlanner::restore_durable(snapshot.clone())?;
            if planner.stage() == garth::DirectConversationRepairStage::Enqueued {
                candidates.push((request_id.clone(), planner));
            }
        }
        let Some((request_id, mut planner)) = candidates.pop() else {
            return Ok(None);
        };
        if !candidates.is_empty() {
            anyhow::bail!("multiple repairs await the same exact KeyPackage Welcome");
        }
        planner.record_welcome_durable(welcome_digest)?;
        self.save_direct_conversation_repair(&planner)?;
        Ok(Some(request_id))
    }

    /// Every durably persisted repair for one Direct Conversation Realm, with
    /// the restart-safe stage each snapshot restores to. `restore_durable` is
    /// the stage authority (a committed pending-durability enqueue reads back
    /// as `Enqueued`), and a tampered snapshot fails the whole query closed.
    pub(crate) fn direct_conversation_repair_requests_for_realm(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Vec<(String, garth::DirectConversationRepairStage)>> {
        let state = self.load();
        let mut requests = Vec::new();
        for (request_id, snapshot) in &state.direct_conversation_repairs {
            if snapshot.route.coordinates.realm_id.as_str() != realm_id {
                continue;
            }
            let planner =
                garth::DirectConversationRepairPlanner::restore_durable(snapshot.clone())?;
            requests.push((request_id.clone(), planner.stage()));
        }
        Ok(requests)
    }

    pub(crate) fn record_direct_conversation_repair_activation(
        &mut self,
        request_id: &str,
        activation_event_id: arkret_sdk::EventId,
    ) -> anyhow::Result<()> {
        let mut planner = self
            .direct_conversation_repair(request_id)?
            .ok_or_else(|| anyhow::anyhow!("unknown Direct Conversation repair request"))?;
        planner.record_activation_durable(activation_event_id)?;
        self.save_direct_conversation_repair(&planner)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::{Duration, TimeZone, Utc};

    use super::*;

    const REALM: &str = "ak:realm:AYTizpS7V46uVDj9LqO0BPE3_FECz9BlgZFE-dQ6bqF3";
    const REJOIN: &str = "ak:event:AXmtMMsFCgaqoViWB_h9mzuZPtig7XaopkKVmS4FA0C_";
    const AUTHORIZE: &str = "ak:event:ASJHfB5f-5oCgYCWweVEcwgoqhJVEz5hiSbZjYXGGYiB";
    const BINDING: &str = "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6";

    fn temp_path(name: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("inkson-repair-{name}-{stamp}.json"))
    }

    fn hash(byte: char) -> arkret_sdk::Hash {
        arkret_sdk::Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn principal() -> arkret_sdk::DidCoreId {
        arkret_sdk::DidCoreId::new("ak:did_core:key:z6MkRepairRequester").unwrap()
    }

    fn content() -> arkret_sdk::MemberRepairRequestPayload {
        arkret_sdk::MemberRepairRequestPayload {
            realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
            requester_principal_id: principal(),
            requester: arkret_sdk::MemberRepairRequester::Device {
                requester_device_id: arkret_sdk::DeviceId::new(
                    "ak:device:01989f10-3000-7000-8000-000000000001",
                )
                .unwrap(),
            },
            requester_keypackage_ref: arkret_sdk::NonEmptyString::new("kp-exact-repair-target")
                .unwrap(),
            observed_active_generation_value_digest: hash('b'),
            rejoin_event_id: arkret_sdk::EventId::new(REJOIN).unwrap(),
            created_at: Utc.with_ymd_and_hms(2026, 8, 10, 10, 0, 0).unwrap(),
        }
    }

    fn ready() -> garth::DirectConversationRepairPlanner {
        let route = garth::DirectConversationRepairRoute {
            source_service_id: arkret_sdk::DidCoreId::new("ak:did_core:web:source.example")
                .unwrap(),
            target_service_id: arkret_sdk::DidCoreId::new("ak:did_core:web:target.example")
                .unwrap(),
            coordinates: arkret_sdk::DirectConversationCoordinates {
                pair_key: hash('a'),
                realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
                main_strand_id: arkret_sdk::StrandId::new(
                    "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                )
                .unwrap(),
                binding_event_ref: Some(arkret_sdk::EventId::new(BINDING).unwrap()),
            },
            target_keypackage_ref: arkret_sdk::NonEmptyString::new("kp-exact-repair-target")
                .unwrap(),
        };
        let mut planner = garth::DirectConversationRepairPlanner::new(route).unwrap();
        planner
            .observe_self_rejoin_accepted(
                garth::SelfRejoinAcceptance {
                    realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
                    requester_principal_id: principal(),
                    rejoin_event_id: arkret_sdk::EventId::new(REJOIN).unwrap(),
                    accepted_at: content().created_at + Duration::seconds(1),
                },
                content(),
            )
            .unwrap();
        let signed_at = content().created_at + Duration::seconds(2);
        let verification_method =
            arkret_sdk::DidUrl::new("did:key:z6MkRepairRequester#device").unwrap();
        planner
            .freeze_signed_request(arkret_sdk::DirectConversationRepairDispatchRequest {
                request_id: arkret_sdk::Base64UrlString::new("A".repeat(32)).unwrap(),
                content: content(),
                requester_authorization:
                    arkret_sdk::DirectConversationRepairAuthorization::Device {
                        requester_device_id: arkret_sdk::DeviceId::new(
                            "ak:device:01989f10-3000-7000-8000-000000000001",
                        )
                        .unwrap(),
                        verification_method: verification_method.clone(),
                        device_authorize_event_id: arkret_sdk::EventId::new(AUTHORIZE).unwrap(),
                        signed_at,
                        signature: arkret_sdk::ProtocolSignature {
                            verification_method,
                            created_at: signed_at,
                            jws: arkret_sdk::Base64UrlString::new("repair-signature").unwrap(),
                        },
                    },
            })
            .unwrap();
        planner
    }

    fn enqueue(
        planner: &garth::DirectConversationRepairPlanner,
    ) -> arkret_sdk::DirectConversationRepairEnqueueOutcome {
        let snapshot = planner.snapshot();
        let frozen = snapshot.frozen_dispatch.unwrap();
        arkret_sdk::DirectConversationRepairEnqueueOutcome {
            request_id: frozen.request.request_id,
            request_digest: frozen.request_digest,
            destination_service_id: snapshot.route.target_service_id,
            status: arkret_sdk::DirectConversationRepairEnqueueStatus::Enqueued,
            recipient_target: arkret_sdk::DirectConversationRepairRecipientTarget::HumanPrincipal {
                target_snapshot_digest: hash('c'),
                enqueued_target_count: 1,
            },
            accepted_at: content().created_at + Duration::seconds(3),
        }
    }

    #[test]
    fn realm_query_reports_restart_safe_stage_and_skips_other_realms() {
        let path = temp_path("realm-query");
        let mut planner = ready();
        planner.record_enqueue_outcome(enqueue(&planner)).unwrap();
        let mut store = LocalStateStore::with_path(&path);
        let request_id = store.save_direct_conversation_repair(&planner).unwrap();

        let restarted = LocalStateStore::with_path(path);
        assert_eq!(
            restarted
                .direct_conversation_repair_requests_for_realm(REALM)
                .unwrap(),
            vec![(request_id, garth::DirectConversationRepairStage::Enqueued)]
        );
        assert!(
            restarted
                .direct_conversation_repair_requests_for_realm(
                    "ak:realm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn restart_recovers_pending_enqueue_as_durable_enqueued() {
        let path = temp_path("restart");
        let mut planner = ready();
        planner.record_enqueue_outcome(enqueue(&planner)).unwrap();
        let mut store = LocalStateStore::with_path(&path);
        let request_id = store.save_direct_conversation_repair(&planner).unwrap();

        let restarted = LocalStateStore::with_path(&path);
        assert_eq!(
            restarted
                .direct_conversation_repair(&request_id)
                .unwrap()
                .unwrap()
                .stage(),
            garth::DirectConversationRepairStage::Enqueued
        );
    }

    #[test]
    fn persisted_tamper_and_non_identical_retry_fail_closed() {
        let path = temp_path("tamper");
        let planner = ready();
        let mut store = LocalStateStore::with_path(&path);
        let request_id = store.save_direct_conversation_repair(&planner).unwrap();
        let exact_request = planner.snapshot().frozen_dispatch.unwrap().request;
        let restored = store
            .direct_conversation_repair(&request_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            restored.exact_retry_bytes(&exact_request).unwrap(),
            planner
                .snapshot()
                .frozen_dispatch
                .as_ref()
                .unwrap()
                .canonical_request_bytes
        );
        let mut changed = exact_request;
        changed.request_id = arkret_sdk::Base64UrlString::new("B".repeat(32)).unwrap();
        assert!(restored.exact_retry_bytes(&changed).is_err());

        let mut state = store.load();
        state
            .direct_conversation_repairs
            .get_mut(&request_id)
            .unwrap()
            .frozen_dispatch
            .as_mut()
            .unwrap()
            .canonical_request_bytes
            .push(b' ');
        store.save(state);
        assert!(
            LocalStateStore::with_path(path)
                .direct_conversation_repair(&request_id)
                .is_err()
        );
    }

    #[test]
    fn persisted_exact_keypackage_route_tamper_fails_closed() {
        let path = temp_path("keypackage-tamper");
        let planner = ready();
        let mut store = LocalStateStore::with_path(&path);
        let request_id = store.save_direct_conversation_repair(&planner).unwrap();
        let mut state = store.load();
        state
            .direct_conversation_repairs
            .get_mut(&request_id)
            .unwrap()
            .route
            .target_keypackage_ref =
            arkret_sdk::NonEmptyString::new("kp-attacker-substitute").unwrap();
        store.save(state);

        assert!(
            LocalStateStore::with_path(path)
                .direct_conversation_repair(&request_id)
                .is_err()
        );
    }

    #[test]
    fn pending_enqueue_restart_still_accepts_the_exact_welcome() {
        let path = temp_path("pending-restart-welcome");
        let mut planner = ready();
        planner.record_enqueue_outcome(enqueue(&planner)).unwrap();
        let mut store = LocalStateStore::with_path(&path);
        let request_id = store.save_direct_conversation_repair(&planner).unwrap();

        let mut restarted = LocalStateStore::with_path(path);
        assert_eq!(
            restarted
                .record_consumed_direct_conversation_repair_welcome(
                    REALM,
                    "kp-exact-repair-target",
                    hash('d'),
                )
                .unwrap(),
            Some(request_id.clone())
        );
        assert_eq!(
            restarted
                .direct_conversation_repair(&request_id)
                .unwrap()
                .unwrap()
                .stage(),
            garth::DirectConversationRepairStage::WelcomeDurable
        );
    }

    #[test]
    fn exact_keypackage_and_consumed_welcome_gate_activation_stage() {
        let mut planner = ready();
        planner.record_enqueue_outcome(enqueue(&planner)).unwrap();
        planner.confirm_enqueue_outcome_durable().unwrap();
        let path = temp_path("exact-kp");
        let mut store = LocalStateStore::with_path(path);
        let request_id = store.save_direct_conversation_repair(&planner).unwrap();

        assert!(
            store
                .record_direct_conversation_repair_activation(
                    &request_id,
                    arkret_sdk::EventId::new(AUTHORIZE).unwrap(),
                )
                .is_err()
        );

        assert!(
            store
                .record_consumed_direct_conversation_repair_welcome(
                    REALM,
                    "kp-substitute",
                    hash('d'),
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .direct_conversation_repair(&request_id)
                .unwrap()
                .unwrap()
                .stage(),
            garth::DirectConversationRepairStage::Enqueued
        );
        assert_eq!(
            store
                .record_consumed_direct_conversation_repair_welcome(
                    REALM,
                    "kp-exact-repair-target",
                    hash('d'),
                )
                .unwrap(),
            Some(request_id.clone())
        );
        assert_eq!(
            store
                .direct_conversation_repair(&request_id)
                .unwrap()
                .unwrap()
                .stage(),
            garth::DirectConversationRepairStage::WelcomeDurable
        );
        store
            .record_direct_conversation_repair_activation(
                &request_id,
                arkret_sdk::EventId::new(AUTHORIZE).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .direct_conversation_repair(&request_id)
                .unwrap()
                .unwrap()
                .stage(),
            garth::DirectConversationRepairStage::Activated
        );
    }
}
