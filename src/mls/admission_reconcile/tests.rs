use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arkret_sdk::http_client::own_station_results::{
    OwnStationSessionSnapshot, OwnStationSessionSource, OwnStationStateClient,
};
use serde_json::json;

use super::*;

#[tokio::test]
async fn admission_current_requires_complete_account_cut_and_pages_full_actor_ids() {
    let realm = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    let commit = arkret_wire::RealmCommitId::from_digest([71; 32]);
    for scenario in [
        "complete",
        "partial",
        "missing",
        "foreign_account",
        "reset",
        "poison",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
        store.switch_test_account("did:web:admission-current.example");
        let account = store.active_authority().unwrap();
        let mut members = BTreeSet::new();
        let mut entries = Vec::new();
        for number in 0..137 {
            let actor = arkret_sdk::ActorId::account(crate::test_support::authority_at_station(
                "did:web:same-member.example",
                &format!("did:web:station-{number}.example"),
            ));
            members.insert(actor.to_string());
            entries.push(json!({"selector":{"kind":"member_state","actor_id":actor},
                "source_stream_ref":{"kind":"realm","realm_id":realm},
                "revision":{"commit_id":commit,"stream_position":701},
                "value":{"membership":"join"}}));
        }
        let departed = arkret_sdk::ActorId::account(account.clone());
        entries.push(
            json!({"selector":{"kind":"member_state","actor_id":departed},
            "source_stream_ref":{"kind":"realm","realm_id":realm},
            "revision":{"commit_id":commit,"stream_position":701},
            "value":{"membership":"leave"}}),
        );
        let index = crate::state::CurrentIndex::open(&account, 0, store.current_index_location())
            .await
            .unwrap();
        if scenario != "missing" {
            let heads = json!([{"stream_ref":{"kind":"realm","realm_id":realm},
                "stream_position":701,"commit_id":commit}]);
            for (part, entries) in entries.chunks(69).enumerate() {
                let frame = serde_json::from_value(json!({"kind":"delta","cursor":"ak:cursor:YQ",
                "realms":{realm:{"current":{"realm_id":realm,"governance_generation":"1",
                    "stream_heads":heads,"entries":entries},
                    "baseline":{"snapshot_cursor":"ak:cursor:YQ","cut_revision":1,
                        "coverage":{"realm_id":realm,"stream_heads":heads,
                            "complete_for_authorized_streams":true},"complete":part == 1 && scenario != "partial"}}}})).unwrap();
                let stage = index
                    .stage_frame(store.current_generation(), &frame)
                    .await
                    .unwrap();
                store.commit_current_stage_for_test(stage).unwrap();
            }
        }
        if scenario == "poison" {
            index.poison();
        }
        if scenario == "reset" {
            store.set_current_reset_required(true);
        }
        let shared = Arc::new(Mutex::new(store));
        let reader = shared.clone();
        let writer = shared.clone();
        let handle = crate::runtime::input::StateStoreHandle::new(
            move |read| read(&reader.lock().unwrap()),
            move |write| write(&mut writer.lock().unwrap()),
        );
        let requested_account = if scenario == "foreign_account" {
            crate::test_support::authority("did:web:foreign.example")
        } else {
            account
        };
        let result = read_admission_membership(&handle, realm, &requested_account).await;
        if scenario == "complete" {
            let (joined, current) = result.unwrap();
            assert_eq!(joined, members);
            assert_eq!(current.joined.len(), 137);
            assert!(
                current
                    .joined
                    .values()
                    .all(|revision| revision.stream_position == 701)
            );
        } else {
            assert!(result.is_err(), "{scenario}");
        }
        drop(index);
    }
}

#[test]
fn admission_endpoint_requires_exact_current_join_original() {
    let realm =
        crate::test_support::realm_id("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI");
    let account = crate::test_support::authority("did:web:invitee.example");
    let actor = arkret_sdk::ActorId::account(account.clone());
    let device = crate::test_support::device_id("ak:device:01964137-0000-7000-8000-000000000001");
    let payload = arkret_sdk::InviteAcceptPayload::directed(
        arkret_sdk::InviteId::new("ak:invite:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
            .unwrap(),
        account.clone(),
        arkret_sdk::InvitePreviousState::Pending,
    );
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.invite.accept",
        arkret_sdk::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor.clone(),
        payload.to_value().unwrap(),
        chrono::Utc::now(),
    )
    .unwrap();
    let mut event = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = crate::event_signer::build_ed25519_device_signer(
        [83; 32],
        "did:web:invitee.example",
        device.as_str(),
    );
    signer
        .sign_sdk_event_with_context(
            &mut event,
            crate::event_signer::ProducerProofContext::new()
                .with_digest_suite(arkret_sdk::DigestSuite::Sha256),
        )
        .unwrap();
    event
        .validate_proof_bindings_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
        .unwrap();
    // The commit is a structural storage fixture. Network acceptance and
    // signature verification remain the authenticated AuthorityClient's job.
    let commit = arkret_wire::test_support::structural_realm_commit_at(
        &event,
        realm.clone(),
        701,
        arkret_sdk::DidUrl::new("did:web:authority.example#key-1").unwrap(),
        chrono::Utc::now(),
    );
    let source = arkret_wire::CurrentRevision {
        commit_id: commit.commit_id.clone(),
        stream_position: 701,
    };
    let page = crate::models::BackfillView(arkret_wire::StreamScanResponseBody {
        committed_events: vec![arkret_wire::CommittedEventView::Full(
            arkret_wire::CommittedEventFullView {
                commit,
                event: event.into_event(),
            },
        )],
        readable_floor: None,
        truncated: true,
    });
    let route = member_join_route_from_current_original(&page, &realm, &actor, &source).unwrap();
    assert_eq!(route.destination_id, account.station_id.to_string());
    assert_eq!(route.target_device_id.as_deref(), Some(device.as_str()));
    for scenario in [
        "commit", "position", "stream", "withheld", "actor", "proof", "empty",
    ] {
        let mut page = page.clone();
        match scenario {
            "empty" => page.0.committed_events.clear(),
            "withheld" => {
                page.0.committed_events[0] = arkret_wire::CommittedEventView::Withheld(
                    arkret_wire::CommittedEventWithheldView {
                        commit: page.0.committed_events[0].commit().clone(),
                        event_disclosure: arkret_wire::EventDisclosure {
                            status: arkret_wire::EventDisclosureStatus::Withheld,
                        },
                    },
                )
            }
            _ => {
                let arkret_wire::CommittedEventView::Full(row) = &mut page.0.committed_events[0]
                else {
                    unreachable!()
                };
                match scenario {
                    "commit" => {
                        row.commit.commit_id = arkret_wire::RealmCommitId::from_digest([94; 32])
                    }
                    "position" => row.commit.stream_position = 702,
                    "stream" => {
                        row.commit.stream_ref = arkret_sdk::CommitStreamRef::Realm {
                            realm_id: crate::test_support::realm_id(
                                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                            ),
                        }
                    }
                    "actor" => {
                        row.event.actor_id =
                            arkret_sdk::ActorId::account(crate::test_support::authority_at_station(
                                "did:web:invitee.example",
                                "did:web:other-station.example",
                            ))
                    }
                    "proof" => row.event.producer_proof = None,
                    _ => unreachable!(),
                }
            }
        }
        assert!(
            member_join_route_from_current_original(&page, &realm, &actor, &source).is_err(),
            "{scenario}"
        );
    }
}

#[tokio::test]
async fn complete_current_membership_does_not_scan_accepted_history() {
    let realm = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    let commit = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";
    let directory = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
    assert!(store.switch_test_account("did:web:admission-current.example"));
    let account = store.active_authority().unwrap();
    let actor = arkret_sdk::ActorId::account(account.clone());
    let index = crate::state::CurrentIndex::open(&account, 0, store.current_index_location())
        .await
        .unwrap();
    let heads = json!([{"stream_ref":{"kind":"realm","realm_id":realm},
        "stream_position":701,"commit_id":commit}]);
    let frame = serde_json::from_value(json!({"kind":"delta","cursor":"ak:cursor:YQ",
        "realms":{realm:{"current":{"realm_id":realm,"governance_generation":"1",
            "stream_heads":heads,"entries":[{
                "selector":{"kind":"member_state","actor_id":actor},
                "source_stream_ref":{"kind":"realm","realm_id":realm},
                "revision":{"commit_id":commit,"stream_position":701},
                "value":{"membership":"join"}
            }]},
            "baseline":{"snapshot_cursor":"ak:cursor:YQ","cut_revision":1,
                "coverage":{"realm_id":realm,"stream_heads":heads,
                    "complete_for_authorized_streams":true},"complete":true}}}}))
    .unwrap();
    let stage = index.stage_frame(0, &frame).await.unwrap();
    store.commit_current_stage_for_test(stage).unwrap();
    drop(index);
    assert!(store.current_product_view().is_none(), "the reader is cold");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let stopped = Arc::new(AtomicBool::new(false));
    let stop = stopped.clone();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut scans = Vec::new();
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut connection, _)) => {
                    connection.set_nonblocking(false).unwrap();
                    connection
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut buffer = [0; 4096];
                    let header_end = loop {
                        if let Some(offset) = bytes.windows(4).position(|row| row == b"\r\n\r\n") {
                            break offset + 4;
                        }
                        let n = connection.read(&mut buffer).unwrap();
                        assert!(n > 0);
                        bytes.extend_from_slice(&buffer[..n]);
                    };
                    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                    assert!(headers.starts_with("POST /_arkret/self/streams/scan "));
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    assert!(length <= 4096);
                    while bytes.len() < header_end + length {
                        let n = connection.read(&mut buffer).unwrap();
                        assert!(n > 0);
                        bytes.extend_from_slice(&buffer[..n]);
                    }
                    let request: arkret_wire::StreamScanRequestBody =
                        serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
                    scans.push(request);
                    let body = serde_json::to_string(&arkret_wire::Problem::new(
                        "temporarily_unavailable",
                        503,
                        "owned admission history fixture",
                    ))
                    .unwrap();
                    write!(connection, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/problem+json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "owned history fixture did not finish"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        }
        scans
    });
    let binding = arkret_sdk::StationConnectionBinding {
        service_id: account.station_id.clone(),
        base_url: base.clone(),
        trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
        authentication_metadata: arkret_sdk::AuthenticationMetadata::minimal(),
    };
    struct Source(OwnStationSessionSnapshot);
    impl OwnStationSessionSource for Source {
        fn snapshot(&self) -> arkret_sdk::http_client::Result<OwnStationSessionSnapshot> {
            Ok(self.0.clone())
        }
    }
    let session = OwnStationSessionSnapshot::new(
        binding.clone(),
        account.clone(),
        account.station_id.clone(),
        arkret_wire::SessionGrantId::from_issuance_digest([35; 32]),
        1,
        "admission-current-fixture".into(),
    )
    .unwrap()
    .with_provider_identity(Default::default());
    let raw = arkret_sdk::http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Bearer(
            "admission-current-fixture".into(),
        ))
        .build()
        .unwrap();
    let http = OwnStationStateClient::new(raw, binding, Arc::new(Source(session)))
        .unwrap()
        .http_client()
        .unwrap();
    let _api = crate::transport::TransportClient::from_http(
        http,
        crate::transport::RequestContext::new("admission-current-fixture"),
    );
    let shared = Arc::new(Mutex::new(store));
    let reader = shared.clone();
    let writer = shared.clone();
    let handle = crate::runtime::input::StateStoreHandle::new(
        move |read| read(&reader.lock().unwrap()),
        move |write| write(&mut writer.lock().unwrap()),
    );
    let result = read_admission_membership(&handle, realm, &account).await;
    stopped.store(true, Ordering::Release);
    let scans = server.join().unwrap();
    if !scans.is_empty() {
        assert!(scans.iter().all(|request| request.limit == 500
            && request.direction == arkret_wire::StreamScanDirection::After(None)));
    }
    assert_eq!(
        scans.len(),
        0,
        "complete installed membership needs no Realm history scan"
    );
    let (joined, _) = result.unwrap();
    assert_eq!(joined, BTreeSet::from([actor.to_string()]));
}
