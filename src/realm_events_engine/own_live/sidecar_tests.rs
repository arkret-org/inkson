//! Real bound HTTP recovery, native signatures and the durable private cut.

use std::sync::{Arc, Mutex};

use super::tests::{
    content_burst_fixture, frozen, http_for_account_observed, seal_current_snapshot, test_projector,
};
use super::*;
use crate::test_support::committed_event::{
    FixtureStation, fixture_time, verified_realm_fixture_as,
};

struct PrivateFixture {
    base: arkret_sdk::RealmStateSnapshot,
    rows: Vec<arkret_sdk::CommittedEventFullView>,
    key: serde_json::Value,
}

impl PrivateFixture {
    fn snapshot(&self, end: usize) -> arkret_sdk::RealmStateSnapshot {
        let row = &self.rows[end];
        let mut snapshot = self.base.clone();
        snapshot
            .visible_stream_heads
            .push(arkret_sdk::CommitStreamHead {
                stream_ref: row.commit.stream_ref.clone(),
                stream_position: row.commit.stream_position,
                commit_id: row.commit.commit_id.clone(),
            });
        snapshot
            .retention_and_history_floor
            .stream_floors
            .push(arkret_sdk::StreamHistoryFloor {
                stream_ref: row.commit.stream_ref.clone(),
                oldest_position: 0,
            });
        let CommitStreamRef::Sidecar { sidecar_id, .. } = &row.commit.stream_ref else {
            unreachable!()
        };
        let payload: arkret_sdk::SidecarContextAttachPayload =
            serde_json::from_value(serde_json::to_value(&row.event.payload).unwrap()).unwrap();
        snapshot
            .current_state_entries
            .push(arkret_sdk::TypedCurrentRow::Value {
                selector: arkret_sdk::CurrentSelector::SidecarContext {
                    sidecar_id: sidecar_id.clone(),
                    source_context_ref: payload.source_context_ref,
                },
                source_stream_ref: row.commit.stream_ref.clone(),
                revision: arkret_sdk::CurrentRevision {
                    commit_id: row.commit.commit_id.clone(),
                    stream_position: row.commit.stream_position,
                },
                value: serde_json::to_value(&row.event.payload).unwrap(),
            });
        snapshot.created_at = fixture_time(100 + end as i64);
        seal_current_snapshot(&mut snapshot);
        snapshot
    }

    fn scan(&self, after: Option<u64>, end: usize, withheld: bool) -> serde_json::Value {
        let start = after.map_or(0, |position| position as usize + 1);
        let rows = self.rows[start..=end].iter().map(|row| {
            if withheld {
                serde_json::json!({"commit":row.commit,"event_disclosure":{"status":"withheld"}})
            } else { serde_json::to_value(row).unwrap() }
        }).collect::<Vec<_>>();
        serde_json::json!({"__scan_request": StreamScanRequest {
            realm_id: self.base.realm_id.clone(), stream_ref: self.rows[0].commit.stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(after), limit: (end - start + 1) as u16,
        }, "response":{"committed_events": rows, "readable_floor": {
            "oldest_position":0,"floor_commit_id":self.rows[0].commit.commit_id,"floor_reason":"stream_start"
        }, "truncated":false}})
    }

    fn reads(&self, after: Option<u64>, end: usize, withheld: bool) -> Vec<serde_json::Value> {
        let mut bodies = vec![
            serde_json::to_value(self.snapshot(end)).unwrap(),
            self.scan(after, end, withheld),
        ];
        if !withheld {
            bodies.extend(
                (after.map_or(0, |position| position as usize + 1)..=end)
                    .map(|_| serde_json::json!({"__signer_key":self.key})),
            );
        }
        bodies
    }
}

fn fixture(seed: u8, key: &serde_json::Value) -> PrivateFixture {
    use arkret_test_kit::signed_event::SignedEventFixtureBuilder;
    let station = FixtureStation::did_web();
    let device = "ak:device:0196419b-0000-7000-8000-000000000001";
    let seed = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [seed; 32],
    ));
    let (bundle, ..) = verified_realm_fixture_as(seed, vec![], "alice.example", device);
    let signer = arkret_test_kit::keys::seeded_signer(
        arkret_sdk::Did::new("did:web:alice.example").unwrap(),
        arkret_sdk::DidUrl::new(format!("did:web:alice.example#{device}")).unwrap(),
    );
    let actor = bundle.genesis_event.actor_id.clone();
    let realm_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: bundle.realm_id.clone(),
    };
    let create = SignedEventFixtureBuilder::new(
        "ak.sidecar.create",
        realm_scope.clone(),
        actor.clone(),
        serde_json::json!({}),
    )
    .with_created_at(fixture_time(2))
    .sign_verifiable(&signer)
    .unwrap()
    .expect_verifiable();
    let sidecar_id = arkret_sdk::SidecarId::from_event_id(&create.event_id);
    let mut strand = arkret_models_collaboration::objects::strand::Strand::new_create(
        bundle.realm_id.clone(),
        "Private source",
        actor.clone(),
    );
    strand.created_at = fixture_time(3);
    strand.tracks.clear();
    strand.tracks.insert(
        "discussion".into(),
        arkret_models_collaboration::objects::profiles::StrandTrack::discussion_primary(),
    );
    let source = SignedEventFixtureBuilder::new(
        "ak.strand.create",
        realm_scope,
        actor.clone(),
        serde_json::json!({"object":strand}),
    )
    .with_created_at(fixture_time(3))
    .sign_verifiable(&signer)
    .unwrap()
    .expect_verifiable();
    let strand_id = arkret_sdk::StrandId::from_event_id(&source.event_id);
    let mut realm_items = Vec::<arkret_sdk::CommittedEventFullView>::new();
    let mut previous = bundle.genesis_commit.commit_id.clone();
    for (index, event) in [create, source].into_iter().enumerate() {
        let mut commit = bundle.genesis_commit.clone();
        commit.stream_position = index as u64 + 1;
        commit.previous_commit_ref = Some(previous);
        commit.event_ref = event.event_id.clone();
        commit.committed_at = fixture_time(51 + index as i64);
        commit = station.seal_commit(commit);
        previous = commit.commit_id.clone();
        realm_items.push(arkret_sdk::CommittedEventFullView { commit, event });
    }
    let mut base = frozen(&[CommittedEventView::Full(realm_items[1].clone())]);
    base.current_state_entries = super::super::tests::coland_bootstrap_rows(&bundle, &realm_items);
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: bundle.realm_id.clone(),
        sidecar_id: sidecar_id.clone(),
    };
    let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
    let mut rows = Vec::<arkret_sdk::CommittedEventFullView>::new();
    for position in 0..4 {
        let mut payload = serde_json::json!({"sidecar_id":sidecar_id,
            "source_context_ref":{"kind":"strand","strand_id":strand_id},"version":position+1});
        if let Some(previous) = rows.last() {
            payload["predecessor_event_ref"] = serde_json::json!(previous.event.event_id);
        }
        let event = SignedEventFixtureBuilder::new(
            "ak.sidecar.context.attach",
            scope.clone(),
            actor.clone(),
            payload,
        )
        .with_created_at(fixture_time(4 + position))
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        let fact =
            arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact {
                event_id: event.event_id.clone(),
                actor: event.actual_signer().clone(),
                device_id: event.account_device_producer().unwrap().unwrap().device_id,
                verification_method: event
                    .producer_proof
                    .as_ref()
                    .unwrap()
                    .verification_method
                    .clone(),
                key: serde_json::from_value(key.clone()).unwrap(),
                accepted_at: fixture_time(1),
            };
        let mut commit = bundle.genesis_commit.clone();
        commit.stream_ref = stream.clone();
        commit.stream_position = position as u64;
        commit.previous_commit_ref = rows.last().map(|row| row.commit.commit_id.clone());
        commit.event_ref = event.event_id.clone();
        commit.committed_at = fixture_time(54 + position);
        commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
        rows.push(arkret_sdk::CommittedEventFullView {
            commit: station.seal_commit(commit),
            event,
        });
    }
    PrivateFixture {
        base,
        rows,
        key: key.clone(),
    }
}

fn local_store(path: &std::path::Path) -> Arc<Mutex<crate::state::LocalStateStore>> {
    let account = crate::test_support::AccountFixture::new("did:web:alice.example")
        .station("ak:did_core:web:station.example")
        .build();
    let mut store = crate::state::LocalStateStore::with_path(path);
    store.switch_active_account(&account).unwrap();
    Arc::new(Mutex::new(store))
}

#[tokio::test]
async fn ten_legal_sidecars_only_the_changed_stream_reads_one_tail_row() {
    let (_, _, key) = content_burst_fixture();
    // One Sidecar per controller/Realm, retaining independent Realm cuts.
    let fixtures = (30..40).map(|seed| fixture(seed, &key)).collect::<Vec<_>>();
    let mut bodies = fixtures
        .iter()
        .flat_map(|fixture| fixture.reads(None, 1, false))
        .collect::<Vec<_>>();
    bodies.extend(fixtures[0].reads(Some(1), 2, false));
    bodies.extend(
        fixtures[1..]
            .iter()
            .map(|fixture| serde_json::to_value(fixture.snapshot(1)).unwrap()),
    );
    let observed = Arc::new(Mutex::new(Vec::new()));
    let account = fixtures[0].rows[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let (client, _, server) =
        http_for_account_observed(bodies, account, None, Some(observed.clone()));
    let directory = tempfile::tempdir().unwrap();
    let store = local_store(&directory.path().join("ten-private.json"));
    let mut replicas = Vec::new();
    for fixture in &fixtures {
        let realm = &fixture.base.realm_id;
        let projector = test_projector(store.clone(), realm);
        let mut replica = OwnStationReplica::new(realm.clone());
        refresh_sidecars(
            &client,
            &client.http_client().unwrap(),
            realm,
            &projector,
            &|| true,
            &mut replica,
        )
        .await
        .unwrap();
        replicas.push(replica);
    }
    let before = observed.lock().unwrap().len();
    for (index, fixture) in fixtures.iter().enumerate() {
        let realm = &fixture.base.realm_id;
        refresh_sidecars(
            &client,
            &client.http_client().unwrap(),
            realm,
            &test_projector(store.clone(), realm),
            &|| true,
            &mut replicas[index],
        )
        .await
        .unwrap();
        let expected = &fixture.rows[if index == 0 { 2 } else { 1 }].commit;
        assert_eq!(
            replicas[index]
                .head(&expected.stream_ref)
                .unwrap()
                .commit_id,
            expected.commit_id
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .verified_commit_stream_cursor(&expected.stream_ref)
                .unwrap()
                .unwrap()
                .commit_id,
            expected.commit_id
        );
    }
    server.join().unwrap();
    let requests = observed.lock().unwrap();
    let followup = &requests[before..];
    assert_eq!(
        followup
            .iter()
            .filter(|request| request.starts_with("get "))
            .count(),
        10
    );
    assert_eq!(
        followup
            .iter()
            .filter(|request| request.contains("/streams/scan"))
            .count(),
        1
    );
    assert_eq!(
        followup
            .iter()
            .filter(|request| request.contains("/signer-keys/query"))
            .count(),
        1
    );
}

#[tokio::test]
async fn cold_private_recovery_reaccepts_originals_instead_of_reusing_persistent_coordinates() {
    let (_, _, key) = content_burst_fixture();
    let fixture = fixture(41, &key);
    let mut bodies = fixture.reads(None, 1, false);
    bodies.extend(fixture.reads(None, 1, false));
    let account = fixture.rows[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let (client, source, server) = http_for_account_observed(bodies, account, None, None);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cold-private.json");
    let store = local_store(&path);
    let realm = &fixture.base.realm_id;
    let mut old = OwnStationReplica::new(realm.clone());
    refresh_sidecars(
        &client,
        &client.http_client().unwrap(),
        realm,
        &test_projector(store.clone(), realm),
        &|| true,
        &mut old,
    )
    .await
    .unwrap();
    let prior = source.0.lock().unwrap().clone();
    *source.0.lock().unwrap() =
        arkret_sdk::http_client::own_station_results::OwnStationSessionSnapshot::new(
            prior.binding().clone(),
            prior.account_id().clone(),
            prior.binding().service_id.clone(),
            prior.grant_id().clone(),
            prior.epoch() + 1,
            "test-grant".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
    let raw = arkret_sdk::http_client::ClientBuilder::new(
        url::Url::parse(&prior.binding().base_url).unwrap(),
    )
    .allow_insecure_localhost()
    .auth(arkret_sdk::http_client::Auth::Bearer("test-grant".into()))
    .build()
    .unwrap();
    let client = OwnStationResultClient::new(raw, prior.binding().clone(), source).unwrap();
    assert!(
        old.complete_sidecar_head(&client, &fixture.rows[0].commit.stream_ref)
            .is_err()
    );
    *store.lock().unwrap() = Arc::try_unwrap(local_store(&path))
        .ok()
        .unwrap()
        .into_inner()
        .unwrap();
    let mut cold = OwnStationReplica::new(realm.clone());
    refresh_sidecars(
        &client,
        &client.http_client().unwrap(),
        realm,
        &test_projector(store.clone(), realm),
        &|| true,
        &mut cold,
    )
    .await
    .unwrap();
    server.join().unwrap();
    assert!(
        cold.complete_sidecar_head(&client, &fixture.rows[0].commit.stream_ref)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_tail_failure_never_advances_the_durable_cut_and_retries_independently() {
    let (_, _, key) = content_burst_fixture();
    for refusal in [
        "withheld",
        "flush",
        "floor",
        "floor_flush",
        "fork",
        "superseded",
    ] {
        let fixture = fixture(42, &key);
        let mut bodies = fixture.reads(None, 1, false);
        let mut rejected = fixture.snapshot(2);
        if refusal.starts_with("floor") {
            rejected.retention_and_history_floor.stream_floors[1].oldest_position = 1;
        }
        if refusal == "fork" {
            rejected = fixture.snapshot(1);
            let wrong = arkret_sdk::RealmCommitId::from_digest([99; 32]);
            rejected.visible_stream_heads[1].commit_id = wrong.clone();
            let arkret_sdk::TypedCurrentRow::Value { revision, .. } =
                rejected.current_state_entries.last_mut().unwrap();
            revision.commit_id = wrong;
        }
        seal_current_snapshot(&mut rejected);
        if refusal == "superseded" {
            bodies.push(serde_json::to_value(fixture.snapshot(3)).unwrap());
        }
        bodies.push(serde_json::to_value(rejected).unwrap());
        if !matches!(refusal, "floor" | "floor_flush" | "fork") {
            bodies.push(fixture.scan(Some(1), 2, refusal == "withheld"));
            if refusal != "withheld" {
                bodies.push(serde_json::json!({"__signer_key":key}));
            }
        }
        if !matches!(refusal, "superseded" | "floor" | "floor_flush") {
            bodies.extend(fixture.reads(Some(1), 2, false));
        }
        let account = fixture.rows[0]
            .event
            .actor_id
            .as_account_id()
            .unwrap()
            .clone();
        let (client, _, server) = http_for_account_observed(bodies, account, None, None);
        let directory = tempfile::tempdir().unwrap();
        let store = local_store(&directory.path().join("failed-private.json"));
        let realm = &fixture.base.realm_id;
        let projector = test_projector(store.clone(), realm);
        let mut replica = OwnStationReplica::new(realm.clone());
        refresh_sidecars(
            &client,
            &client.http_client().unwrap(),
            realm,
            &projector,
            &|| true,
            &mut replica,
        )
        .await
        .unwrap();
        let generation = store.lock().unwrap().current_generation();
        let durable = store
            .lock()
            .unwrap()
            .conformance_account_checkpoint_token()
            .unwrap();
        if matches!(refusal, "flush" | "floor_flush") {
            store
                .lock()
                .unwrap()
                .conformance_fail_account_commit(true)
                .unwrap();
        }
        if refusal == "superseded" {
            let newer = client.snapshot_head(realm).await.unwrap();
            store
                .lock()
                .unwrap()
                .install_own_station_sidecar_current(&newer)
                .unwrap();
        }
        assert!(
            refresh_sidecars(
                &client,
                &client.http_client().unwrap(),
                realm,
                &projector,
                &|| true,
                &mut replica
            )
            .await
            .is_err(),
            "{refusal}"
        );
        let head = &fixture.rows[1].commit;
        assert_eq!(
            replica.head(&head.stream_ref).unwrap().commit_id,
            head.commit_id,
            "{refusal}"
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .verified_commit_stream_cursor(&head.stream_ref)
                .unwrap()
                .unwrap()
                .commit_id,
            head.commit_id,
            "{refusal}"
        );
        assert_eq!(
            store.lock().unwrap().current_generation(),
            generation,
            "{refusal}"
        );
        if refusal.starts_with("floor") {
            assert!(
                store
                    .lock()
                    .unwrap()
                    .verified_sidecar_inputs(realm.as_str())
                    .is_err(),
                "a newly unreadable floor must withdraw the old private view: {refusal}"
            );
        } else {
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .conformance_account_checkpoint_token()
                    .unwrap(),
                durable,
                "{refusal}"
            );
        }
        if matches!(refusal, "flush" | "floor_flush") {
            store
                .lock()
                .unwrap()
                .conformance_fail_account_commit(false)
                .unwrap();
        }
        if !matches!(refusal, "superseded" | "floor" | "floor_flush") {
            refresh_sidecars(
                &client,
                &client.http_client().unwrap(),
                realm,
                &projector,
                &|| true,
                &mut replica,
            )
            .await
            .unwrap();
            assert_eq!(replica.head(&head.stream_ref).unwrap().stream_position, 2);
        }
        server.join().unwrap();
    }
}
