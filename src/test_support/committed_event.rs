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

/// Fixture timeline: `1_800_000_000 + seconds`.
pub(crate) fn fixture_time(seconds: i64) -> chrono::DateTime<Utc> {
    time(seconds)
}

/// The governing Station that signs a fixture's Commits, bundle and
/// Snapshots. The mutable did:web Station suits current-key tests; the
/// did:webvh Station also carries the complete method history Garth's
/// historical key directory requires.
pub(crate) struct FixtureStation {
    method: DidUrl,
    service_id: DidCoreId,
    route: Value,
    key: SigningKey,
    resolution: Option<arkret_models_identity::AuthenticatedServiceResolution>,
}

impl FixtureStation {
    pub(crate) fn did_web() -> Self {
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let method = DidUrl::new(format!("{STATION}#realm-authority")).unwrap();
        let key_multibase = arkret_sdk::canonical::ed25519_pubkey_to_did_key_multibase(
            key.verifying_key().as_bytes(),
        );
        let document: arkret_models_identity::DidDocument = serde_json::from_value(json!({
            "@context": ["https://www.w3.org/ns/did/v1"], "id": STATION,
            "verificationMethod": [{"id":method, "controller":STATION,
                "type":"Multikey", "publicKeyMultibase":key_multibase}],
            "authentication":[method], "assertionMethod":[method],
            "service":[{"id":format!("{STATION}#station"), "type":"ArkretService",
                "serviceEndpoint":"https://station.example/", "serviceKind":"station"}]
        }))
        .unwrap();
        let service_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let route = arkret_identity::build_authenticated_did_web_service_resolution(
            service_id.clone(),
            "station".to_owned(),
            document,
            time(100),
        )
        .unwrap();
        Self {
            method,
            service_id,
            route: serde_json::to_value(route).unwrap(),
            key,
            resolution: None,
        }
    }

    /// A did:webvh Station incepted at `inception_at` whose signing method
    /// is derived from `seed`.
    pub(crate) fn webvh(seed: u8, inception_at: chrono::DateTime<Utc>) -> Self {
        use rand_core::SeedableRng as _;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(seed));
        let prepared = arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
            &mut rng,
            &arkret_signatures::webvh::ServiceInceptionInput {
                principal_endpoint: &url::Url::parse("https://station.example/").unwrap(),
                local_id: "service",
                also_known_as: &[],
                version_time: inception_at,
                did_key_fragment: Some("realm-authority"),
            },
            &[seed; 32],
        )
        .unwrap();
        let did = Did::new(prepared.did.clone()).unwrap();
        let service_id = arkret_sdk::project_did_to_core_id(&did).unwrap();
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            service_id.clone(),
            "station".to_owned(),
            serde_json::from_value(prepared.log_entry["state"].clone()).unwrap(),
            vec![prepared.log_entry.clone()],
            vec![],
            inception_at + Duration::seconds(30),
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[seed; 32]);
        assert_eq!(
            arkret_sdk::canonical::ed25519_pubkey_to_did_key_multibase(
                key.verifying_key().as_bytes()
            ),
            prepared.did_public_key_multibase,
            "the did:webvh method key is the seeded signing key"
        );
        Self {
            method: DidUrl::new(prepared.did_key_id.clone()).unwrap(),
            service_id,
            route: serde_json::to_value(&resolution).unwrap(),
            key,
            resolution: Some(resolution),
        }
    }

    pub(crate) fn service_id(&self) -> &DidCoreId {
        &self.service_id
    }

    /// The complete method-native history Garth resolves historical keys
    /// from; `None` for the mutable did:web Station.
    pub(crate) fn resolution(
        &self,
    ) -> Option<&arkret_models_identity::AuthenticatedServiceResolution> {
        self.resolution.as_ref()
    }

    fn initial_signature(&self, context: DetachedSignatureContext) -> DetachedObjectSignature {
        sign_detached_object(
            &json!({}),
            context,
            self.method.clone(),
            time(50),
            &self.key,
        )
        .unwrap()
    }

    pub(crate) fn seal_commit(&self, mut commit: RealmCommit) -> RealmCommit {
        let unsigned =
            arkret_sdk::canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
        commit.signature = sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmCommit,
            self.method.clone(),
            time(50),
            &self.key,
        )
        .unwrap();
        commit
    }

    /// Re-issue a fixture bundle and its current assertion at `issued_at`
    /// for a caller's fresh authority nonce, as the governing Station
    /// answers each request.
    pub(crate) fn reassert_for_nonce(
        &self,
        bundle: &mut RealmAuthorityBundle,
        nonce: Base64UrlString,
        issued_at: chrono::DateTime<Utc>,
    ) {
        bundle.bundle_issued_at = issued_at;
        bundle.current_assertion.nonce = nonce;
        bundle.current_assertion.expires_at = issued_at + Duration::seconds(300);
        let unsigned = arkret_sdk::canonical::canonical::unsigned_value(
            &bundle.current_assertion,
            &["signature"],
        )
        .unwrap();
        bundle.current_assertion.signature = sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            self.method.clone(),
            issued_at,
            &self.key,
        )
        .unwrap();
    }

    /// Re-address and sign a Snapshot at its own `created_at`.
    pub(crate) fn sign_snapshot(&self, snapshot: &mut arkret_sdk::RealmStateSnapshot) {
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
            self.method.clone(),
            snapshot.created_at,
            &self.key,
        )
        .unwrap();
    }
}

/// Re-address and sign a Snapshot as the fixture Station, whose method and
/// key are the ones [`verified_realm_fixture_as`] puts in its key directory.
pub(crate) fn sign_fixture_snapshot(snapshot: &mut arkret_sdk::RealmStateSnapshot) {
    FixtureStation::did_web().sign_snapshot(snapshot);
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
    verified_realm_fixture_signed_by(
        &FixtureStation::did_web(),
        realm_id,
        json!({}),
        entries,
        principal,
        device_id,
    )
}

/// One contiguous signed Realm stream governed by `station`, whose genesis
/// Event carries `genesis_payload`. An empty tail keeps its head at genesis.
pub(crate) fn verified_realm_fixture_signed_by(
    station: &FixtureStation,
    realm_id: RealmId,
    genesis_payload: Value,
    entries: Vec<(String, Value)>,
    principal: &str,
    device_id: &str,
) -> (
    RealmAuthorityBundle,
    RealmAuthorityKeyMap,
    Vec<CommittedEventFullView>,
) {
    let event_signer = arkret_test_kit::keys::seeded_signer(
        Did::new(format!("did:web:{principal}")).unwrap(),
        DidUrl::new(format!("did:web:{principal}#{device_id}")).unwrap(),
    );
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let actor = ActorId::account(arkret_sdk::AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:{principal}")).unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let signed = |kind: &str, payload: Value, at| {
        SignedEventFixtureBuilder::new(kind, scope.clone(), actor.clone(), payload)
            .with_created_at(at)
            .sign_verifiable(&event_signer)
            .unwrap()
            .expect_verifiable()
    };
    let genesis = signed(EventKind::RealmCreate.as_str(), genesis_payload, time(0));
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
    let genesis_commit = station.seal_commit(RealmCommit {
        commit_id: RealmCommitId::from_digest([0x51; 32]),
        realm_id: realm_id.clone(),
        stream_ref: stream_ref.clone(),
        stream_position: 0,
        previous_commit_ref: None,
        event_ref: genesis.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone()),
        committed_at: time(50),
        producer_signer_fact_digest: None,
        signature: station.initial_signature(DetachedSignatureContext::RealmCommit),
    });
    let mut previous = genesis_commit.commit_id.clone();
    let items = events
        .into_iter()
        .enumerate()
        .map(|(index, event)| {
            let position = (index + 1) as u64;
            let commit = station.seal_commit(RealmCommit {
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
                producer_signer_fact_digest: None,
                signature: station.initial_signature(DetachedSignatureContext::RealmCommit),
            });
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
        current_service_id: station.service_id.clone(),
        last_handoff_ref: None,
        realm_stream_head: head.clone(),
        nonce: Base64UrlString::new(NONCE.to_owned()).unwrap(),
        expires_at: time(400),
        signature: station
            .initial_signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
    };
    let unsigned =
        arkret_sdk::canonical::canonical::unsigned_value(&assertion, &["signature"]).unwrap();
    assertion.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        station.method.clone(),
        time(50),
        &station.key,
    )
    .unwrap();
    let bundle = RealmAuthorityBundle {
        realm_id: realm_id.clone(),
        genesis_event: genesis,
        genesis_commit,
        authority_transitions: vec![],
        current_generation: 0,
        current_service_id: station.service_id.clone(),
        current_route_record: station.route.clone(),
        realm_stream_head: head,
        bundle_issued_at: time(50),
        current_assertion: assertion,
    };
    let keys = RealmAuthorityKeyMap::new().with_key(
        &station.method,
        PublicKeyMaterial::Ed25519Raw {
            bytes: station.key.verifying_key().to_bytes().to_vec(),
        },
    );
    let freshness =
        RealmAuthorityFreshness::new(time(100), Base64UrlString::new(NONCE.to_owned()).unwrap());
    let verified = verify_realm_authority_bundle(&bundle, &freshness, &keys).unwrap();
    for item in &items {
        verified.verify_committed_item(item, &keys).unwrap();
        let mut altered = item.clone();
        altered.commit.commit_id = RealmCommitId::from_digest([0x73; 32]);
        assert!(verified.verify_committed_item(&altered, &keys).is_err());
    }
    (bundle, keys, items)
}
