use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use arkret_sdk::http_client::own_station_results::{
    OwnStationSessionIdentity, OwnStationSessionSource, OwnStationStateClient,
};
use tokio::sync::oneshot;

use super::*;

fn session(
    principal: &str,
    station: &str,
    base: &str,
    epoch: u64,
    identity: OwnStationSessionIdentity,
) -> OwnStationSessionSnapshot {
    let account = arkret_sdk::AccountId {
        principal_id: arkret_sdk::DidCoreId::new(principal).unwrap(),
        station_id: arkret_sdk::DidCoreId::new(station).unwrap(),
    };
    let binding = arkret_sdk::StationConnectionBinding {
        service_id: account.station_id.clone(),
        base_url: base.into(),
        trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
        authentication_metadata: arkret_sdk::AuthenticationMetadata::minimal(),
    };
    OwnStationSessionSnapshot::new(
        binding,
        account.clone(),
        account.station_id,
        arkret_wire::SessionGrantId::from_issuance_digest([51; 32]),
        epoch,
        "projection-fixture".into(),
    )
    .unwrap()
    .with_provider_identity(identity)
}

fn key() -> ReadKey {
    ReadKey {
        session: session(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
            "https://station.example/",
            1,
            Default::default(),
        ),
        realm: RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [52; 32],
        )),
        read_fence: Default::default(),
    }
}

struct Dropped(Arc<AtomicUsize>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn one_waiter_leaving_keeps_the_single_read_alive_for_the_other() {
    let mut reads = ReadFlights::<u32>::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let (send, receive) = oneshot::channel();
    let key = key();
    let first = reads.join(key.clone(), || {
        let calls = calls.clone();
        let dropped = dropped.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let _guard = Dropped(dropped);
            Ok(Arc::new(vec![receive.await.unwrap()]))
        })
    });
    assert!(first.clone().now_or_never().is_none());
    let second = reads.join(key, || panic!("duplicate projection request"));
    drop(first);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    send.send(7).unwrap();
    assert_eq!(*second.await.unwrap(), vec![7]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn all_waiters_leaving_cancels_the_read_and_allows_a_new_attempt() {
    let mut reads = ReadFlights::<u32>::default();
    let dropped = Arc::new(AtomicUsize::new(0));
    let key = key();
    let first = reads.join(key.clone(), || {
        let dropped = dropped.clone();
        Box::pin(async move {
            let _guard = Dropped(dropped);
            futures_util::future::pending().await
        })
    });
    assert!(first.clone().now_or_never().is_none());
    drop(first);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        *reads
            .join(key, || Box::pin(async { Ok(Arc::new(vec![8])) }))
            .await
            .unwrap(),
        vec![8]
    );
}

#[tokio::test]
async fn a_completed_result_is_not_cached_behind_a_slow_original_waiter() {
    let mut reads = ReadFlights::<u32>::default();
    let key = key();
    let first = reads.join(key.clone(), || Box::pin(async { Ok(Arc::new(vec![1])) }));
    let slow = reads.join(key.clone(), || panic!("duplicate request"));
    assert_eq!(*first.await.unwrap(), vec![1]);
    let next = reads.join(key, || Box::pin(async { Ok(Arc::new(vec![2])) }));
    assert_eq!(*next.await.unwrap(), vec![2]);
    assert_eq!(*slow.await.unwrap(), vec![1]);
}

#[tokio::test]
async fn shared_failure_keeps_its_sdk_classification_and_does_not_poison_retry() {
    let mut reads = ReadFlights::<u32>::default();
    let key = key();
    let (send, receive) = oneshot::channel();
    let first = reads.join(key.clone(), || {
        Box::pin(async move {
            receive.await.unwrap();
            Err(ReadFailure::from(anyhow::Error::from(
                arkret_sdk::http_client::Error::Protocol("fixture-format".into()),
            )))
        })
    });
    assert!(first.clone().now_or_never().is_none());
    let second = reads.join(key.clone(), || panic!("duplicate failure request"));
    send.send(()).unwrap();
    let (first, second) = futures_util::future::join(first, second).await;
    let first = first.unwrap_err();
    let second = second.unwrap_err();
    assert!(Arc::ptr_eq(&first.0, &second.0));
    assert!(crate::api_error::is_response_format_error(
        &anyhow::Error::new(first)
    ));
    assert_eq!(
        *reads
            .join(key, || Box::pin(async { Ok(Arc::new(vec![3])) }))
            .await
            .unwrap(),
        vec![3]
    );
}

#[tokio::test]
async fn complete_account_station_origin_epoch_provider_and_realm_are_independent() {
    let mut reads = ReadFlights::<u32>::default();
    let identity = OwnStationSessionIdentity::default();
    let original = ReadKey {
        session: session(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
            "https://station.example/",
            1,
            identity.clone(),
        ),
        realm: key().realm,
        read_fence: Default::default(),
    };
    let mut other_realm = original.clone();
    other_realm.realm = RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [53; 32],
    ));
    let variants = [
        original.clone(),
        other_realm,
        ReadKey {
            session: session(
                "ak:did_core:web:bob.example",
                "ak:did_core:web:station.example",
                "https://station.example/",
                1,
                identity.clone(),
            ),
            ..original.clone()
        },
        ReadKey {
            session: session(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:other.example",
                "https://other.example/",
                1,
                identity.clone(),
            ),
            ..original.clone()
        },
        ReadKey {
            session: session(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:station.example",
                "https://moved.example/",
                1,
                identity.clone(),
            ),
            ..original.clone()
        },
        ReadKey {
            session: session(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:station.example",
                "https://station.example/",
                2,
                identity.clone(),
            ),
            ..original.clone()
        },
        ReadKey {
            session: OwnStationSessionSnapshot::new(
                original.session.binding().clone(),
                original.session.account_id().clone(),
                original.session.account_id().station_id.clone(),
                arkret_wire::SessionGrantId::from_issuance_digest([54; 32]),
                1,
                "different-device-bound-grant".into(),
            )
            .unwrap()
            .with_provider_identity(identity.clone()),
            ..original.clone()
        },
        // Byte-identical account/grant/epoch in a new provider is an ABA login.
        ReadKey {
            session: session(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:station.example",
                "https://station.example/",
                1,
                Default::default(),
            ),
            ..original.clone()
        },
    ];
    let mut held = Vec::new();
    for key in variants {
        let mut made = false;
        held.push(reads.join(key, || {
            made = true;
            Box::pin(futures_util::future::pending())
        }));
        assert!(made, "different read scopes must not share a flight");
    }
    assert_eq!(held.len(), 8);
}

struct Source(Mutex<OwnStationSessionSnapshot>);

#[tokio::test]
async fn rejoin_cannot_share_the_previous_membership_intervals_read() {
    let mut reads = ReadFlights::<u32>::default();
    let old = key();
    let old_read = reads.join(old.clone(), || Box::pin(futures_util::future::pending()));
    let current = ReadKey {
        read_fence: crate::state::RealmListReadFence::after_removal_for_test(41),
        ..old
    };
    let mut made = false;
    let current_read = reads.join(current.clone(), || {
        made = true;
        Box::pin(async { Ok(Arc::new(vec![2])) })
    });
    assert!(
        made,
        "the same login after rejoin must not reuse the pre-leave read"
    );
    assert_eq!(*current_read.await.unwrap(), vec![2]);
    drop(old_read);
    let newer = ReadKey {
        read_fence: crate::state::RealmListReadFence::after_removal_for_test(43),
        ..current
    };
    assert_eq!(
        *reads
            .join(newer, || Box::pin(async { Ok(Arc::new(vec![3])) }))
            .await
            .unwrap(),
        vec![3]
    );
}

impl OwnStationSessionSource for Source {
    fn snapshot(&self) -> arkret_sdk::http_client::Result<OwnStationSessionSnapshot> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn actual_http_exit_coalesces_waiters_and_refuses_a_replaced_session() {
    use std::io::{Read, Write};
    use std::time::Duration;
    for replace_session in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let realm = key().realm;
        let snapshot = session(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
            &base,
            1,
            Default::default(),
        );
        let binding = snapshot.binding().clone();
        let source = Arc::new(Source(Mutex::new(snapshot)));
        let http = arkret_sdk::http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
            .allow_insecure_localhost()
            .auth(arkret_sdk::http_client::Auth::Bearer(
                "projection-fixture".into(),
            ))
            .build()
            .unwrap();
        let http = OwnStationStateClient::new(http, binding, source.clone())
            .unwrap()
            .http_client()
            .unwrap();
        let (started, receive_started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let server_realm = realm.clone();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            while !bytes.windows(4).any(|value| value == b"\r\n\r\n") {
                let count = connection.read(&mut buffer).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&buffer[..count]);
            }
            let request = String::from_utf8(bytes).unwrap();
            assert!(request.starts_with(&format!(
                "GET {} ",
                super::super::realm_projection_path(&server_realm, "spaces", None)
            )));
            started.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            let body =
                serde_json::json!({"realm_id":server_realm,"spaces":[],"total":0,"has_more":false})
                    .to_string();
            write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).unwrap();
        });
        let mut first = Box::pin(spaces(&http, realm.clone(), Some(Default::default())));
        tokio::select! { result = &mut first => panic!("read completed before release: {result:?}"), result = receive_started => result.unwrap() }
        let mut second = Box::pin(spaces(&http, realm.clone(), Some(Default::default())));
        assert!(second.as_mut().now_or_never().is_none());
        drop(first);
        if replace_session {
            *source.0.lock().unwrap() = session(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:station.example",
                &base,
                2,
                Default::default(),
            );
        }
        release.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .unwrap();
        if replace_session {
            assert!(result.unwrap_err().to_string().contains("session changed"));
        } else {
            assert!(result.unwrap().is_empty());
        }
        server.join().unwrap();
    }
}
