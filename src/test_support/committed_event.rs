//! Cryptographically verified committed Event fixtures shared by unit and integration tests.

use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyMap, verify_realm_authority_bundle,
};
use arkret_sdk::{
    ActorId, Base64UrlString, CommitStreamHead, CommitStreamRef, CommittedEventFullView,
    DetachedObjectSignature, DetachedSignatureContext, Did, DidCoreId, DidUrl, EventKind,
    RealmAuthorityBundle, RealmAuthorityCurrentAssertion, RealmCommit, RealmCommitAuthorityRef,
    RealmCommitId, RealmId, ScopeRef,
};
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::sign_detached_object;
use arkret_test_kit::signed_event::SignedEventFixtureBuilder;
use chrono::{Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

const STATION: &str = "did:web:station.example";
const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

fn time(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
}

fn station_id() -> DidCoreId {
    DidCoreId::new("ak:did_core:web:station.example").unwrap()
}

fn method() -> DidUrl {
    DidUrl::new(format!("{STATION}#realm-authority")).unwrap()
}

fn initial_signature(
    context: DetachedSignatureContext,
    key: &SigningKey,
) -> DetachedObjectSignature {
    sign_detached_object(&json!({}), context, method(), time(50), key).unwrap()
}

fn seal_commit(mut commit: RealmCommit, key: &SigningKey) -> RealmCommit {
    let unsigned =
        arkret_sdk::canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        method(),
        time(50),
        key,
    )
    .unwrap();
    commit
}

/// Re-address and sign a Snapshot as the fixture Station, whose method and
/// key are the ones [`verified_realm_fixture_as`] puts in its key directory.
pub(crate) fn sign_fixture_snapshot(snapshot: &mut arkret_sdk::RealmStateSnapshot) {
    let station_key = SigningKey::from_bytes(&[0x71; 32]);
    let mut identity = serde_json::to_value(&*snapshot).unwrap();
    let object = identity.as_object_mut().unwrap();
    object.remove("signature");
    object.remove("snapshot_id");
    snapshot.snapshot_id =
        arkret_sdk::RealmSnapshotId::from_digest(arkret_sdk::canonical::sha256_bytes(
            &arkret_sdk::canonical::canonical::canonical_json_bytes(&identity).unwrap(),
        ));
    let unsigned =
        arkret_sdk::canonical::canonical::unsigned_value(&*snapshot, &["signature"]).unwrap();
    snapshot.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmSnapshot,
        method(),
        snapshot.created_at,
        &station_key,
    )
    .unwrap();
}

/// A signed Event and Station commit checked against a fresh, nonce-bound
/// generation-0 authority chain. The returned pair is fit for accepted
/// projection tests; callers cannot obtain it without verifier success.
pub(crate) fn verified_realm_item(
    realm_id: RealmId,
    kind: &str,
    payload: Value,
) -> CommittedEventFullView {
    verified_realm_items(realm_id, vec![(kind.to_owned(), payload)])
        .into_iter()
        .next()
        .unwrap()
}

pub(crate) fn verified_realm_item_as(
    realm_id: RealmId,
    kind: &str,
    payload: Value,
    principal: &str,
    device_id: &str,
) -> CommittedEventFullView {
    verified_realm_items_as(
        realm_id,
        vec![(kind.to_owned(), payload)],
        principal,
        device_id,
    )
    .into_iter()
    .next()
    .unwrap()
}

/// One contiguous signed Realm stream after a verified genesis Commit.
pub(crate) fn verified_realm_items(
    realm_id: RealmId,
    entries: Vec<(String, Value)>,
) -> Vec<CommittedEventFullView> {
    verified_realm_items_as(
        realm_id,
        entries,
        "alice.example",
        "ak:device:0196419b-0000-7000-8000-000000000001",
    )
}

pub(crate) fn verified_realm_items_as(
    realm_id: RealmId,
    entries: Vec<(String, Value)>,
    principal: &str,
    device_id: &str,
) -> Vec<CommittedEventFullView> {
    verified_realm_fixture_as(realm_id, entries, principal, device_id).2
}

pub(crate) fn verified_realm_fixture_as(
    realm_id: RealmId,
    entries: Vec<(String, Value)>,
    principal: &str,
    device_id: &str,
) -> (
    RealmAuthorityBundle,
    RealmAuthorityKeyMap,
    Vec<CommittedEventFullView>,
) {
    assert!(!entries.is_empty());
    let station_key = SigningKey::from_bytes(&[0x71; 32]);
    let event_signer = arkret_test_kit::keys::seeded_signer(
        Did::new(format!("did:web:{principal}")).unwrap(),
        DidUrl::new(format!("did:web:{principal}#{device_id}")).unwrap(),
    );
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let actor = ActorId::account(arkret_sdk::AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:{principal}")).unwrap(),
        station_id(),
    ));
    let signed = |kind: &str, payload: Value, at| {
        SignedEventFixtureBuilder::new(kind, scope.clone(), actor.clone(), payload)
            .with_created_at(at)
            .sign_verifiable(&event_signer)
            .unwrap()
            .expect_verifiable()
    };
    let genesis = signed(EventKind::RealmCreate.as_str(), json!({}), time(0));
    let events = entries
        .into_iter()
        .enumerate()
        .map(|(index, (kind, payload))| signed(&kind, payload, time(2 + index as i64)))
        .collect::<Vec<_>>();
    let event_key = PublicKeyMaterial::Ed25519Raw {
        bytes: event_signer.verifying_key().to_bytes().to_vec(),
    };
    for signed_event in std::iter::once(&genesis).chain(events.iter()) {
        let transcript = arkret_sdk::canonical::canonical::canonical_json_bytes(
            &signed_event.digest_payload().unwrap(),
        )
        .unwrap();
        arkret_signatures::proof::verify_ed25519_detached_jws_proof(
            signed_event.producer_proof.as_ref().unwrap(),
            &transcript,
            &signed_event.actor_id,
            &event_key,
        )
        .unwrap();
    }
    let stream_ref = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let genesis_commit = seal_commit(
        RealmCommit {
            commit_id: RealmCommitId::from_digest([0x51; 32]),
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: genesis.event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone()),
            committed_at: time(50),
            signature: initial_signature(DetachedSignatureContext::RealmCommit, &station_key),
        },
        &station_key,
    );
    let mut previous = genesis_commit.commit_id.clone();
    let items = events
        .into_iter()
        .enumerate()
        .map(|(index, event)| {
            let position = (index + 1) as u64;
            let commit = seal_commit(
                RealmCommit {
                    commit_id: RealmCommitId::from_digest(
                        [0x52u8.checked_add(index as u8).unwrap(); 32],
                    ),
                    realm_id: realm_id.clone(),
                    stream_ref: stream_ref.clone(),
                    stream_position: position,
                    previous_commit_ref: Some(previous.clone()),
                    event_ref: event.event_id.clone(),
                    governance_generation: 0,
                    authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                        genesis.event_id.clone(),
                    ),
                    committed_at: time(50 + position as i64),
                    signature: initial_signature(
                        DetachedSignatureContext::RealmCommit,
                        &station_key,
                    ),
                },
                &station_key,
            );
            previous = commit.commit_id.clone();
            CommittedEventFullView { commit, event }
        })
        .collect::<Vec<_>>();
    let head = CommitStreamHead {
        stream_ref,
        stream_position: items.len() as u64,
        commit_id: previous,
    };
    let mut assertion = RealmAuthorityCurrentAssertion {
        realm_id: realm_id.clone(),
        current_generation: 0,
        current_service_id: station_id(),
        last_handoff_ref: None,
        realm_stream_head: head.clone(),
        nonce: Base64UrlString::new(NONCE.to_owned()).unwrap(),
        expires_at: time(400),
        signature: initial_signature(
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            &station_key,
        ),
    };
    let unsigned =
        arkret_sdk::canonical::canonical::unsigned_value(&assertion, &["signature"]).unwrap();
    assertion.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        method(),
        time(50),
        &station_key,
    )
    .unwrap();
    let key_multibase = arkret_sdk::canonical::ed25519_pubkey_to_did_key_multibase(
        station_key.verifying_key().as_bytes(),
    );
    let document: arkret_models_identity::DidDocument = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/did/v1"], "id": STATION,
        "verificationMethod": [{"id":method(), "controller":STATION,
            "type":"Multikey", "publicKeyMultibase":key_multibase}],
        "authentication":[method()], "assertionMethod":[method()],
        "service":[{"id":format!("{STATION}#station"), "type":"ArkretService",
            "serviceEndpoint":"https://station.example/", "serviceKind":"station"}]
    }))
    .unwrap();
    let route = arkret_identity::build_authenticated_did_web_service_resolution(
        station_id(),
        "station".to_owned(),
        document,
        time(100),
    )
    .unwrap();
    let bundle = RealmAuthorityBundle {
        realm_id: realm_id.clone(),
        genesis_event: genesis,
        genesis_commit,
        authority_transitions: vec![],
        current_generation: 0,
        current_service_id: station_id(),
        current_route_record: serde_json::to_value(route).unwrap(),
        realm_stream_head: head,
        bundle_issued_at: time(50),
        current_assertion: assertion,
    };
    let keys = RealmAuthorityKeyMap::new().with_key(
        &method(),
        PublicKeyMaterial::Ed25519Raw {
            bytes: station_key.verifying_key().to_bytes().to_vec(),
        },
    );
    let freshness = RealmAuthorityFreshness::new(
        time(100),
        Base64UrlString::new(NONCE.to_owned()).unwrap(),
        Duration::seconds(300),
    )
    .unwrap();
    let verified = verify_realm_authority_bundle(&bundle, &freshness, &keys).unwrap();
    for item in &items {
        verified.verify_committed_item(item, &keys).unwrap();
        let mut altered = item.clone();
        altered.commit.commit_id = RealmCommitId::from_digest([0x73; 32]);
        assert!(verified.verify_committed_item(&altered, &keys).is_err());
    }
    (bundle, keys, items)
}
