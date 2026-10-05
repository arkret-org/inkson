//! Real RFC 9420 fixtures for the disposable fold validation cache. The local
//! accepted-carrier seams isolate MLS restoration and producer verification;
//! Station admission itself is covered by the native replay suite.

use super::*;
use crate::secure_key_store::MemorySecureKeyStore;
use crate::test_support as fixture;

const AGENT_DID: &str = "did:web:fold-agent.example";
const AGENT_METHOD: &str = "did:web:fold-agent.example#runtime";
const AGENT_SEED: [u8; 32] = [31; 32];

fn id(byte: u8) -> EventId {
    EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [byte; 32])
}

struct MlsFixture {
    _directory: tempfile::TempDir,
    store: LocalStateStore,
    secure: MemorySecureKeyStore,
    controller: AccountId,
    scope: ScopeRef,
    agent: arkret_sdk::ActorId,
    sender: arkret_sdk::ArkretMlsGroup,
    state_ref: EventId,
}

impl MlsFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
        store.switch_test_account("did:web:fold-controller.example");
        let controller = store.active_authority().unwrap();
        let device = fixture::device_id("ak:device:01904100-0000-7000-8000-0000000000c1");
        let agent = arkret_sdk::ActorId::account(AccountId::new(
            fixture::core_id(AGENT_DID),
            controller.station_id.clone(),
        ));
        let realm = arkret_sdk::RealmId::from_event_id(&id(8));
        let scope = ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&id(9)),
        };
        let creator = arkret_sdk::ArkretMlsIdentity::new_agent(
            agent.clone(),
            arkret_sdk::DidUrl::new(AGENT_METHOD).unwrap(),
            id(31),
            arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&AGENT_SEED),
            ),
        )
        .unwrap();
        let reader = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            arkret_sdk::ActorId::account(controller.clone()),
            device.clone(),
        )
        .unwrap();
        let endpoints = vec![creator.endpoint_identity(), reader.endpoint_identity()];
        let package = fixture::claimed_mls_key_package(
            reader.key_package_record().unwrap(),
            1_760_000_000_011,
        );
        let mut sender = creator.create_group(&scope).unwrap();
        sender
            .install_local_creator_binding(agent.clone(), None)
            .unwrap();
        let base = id(21);
        let ScopeRef::Sidecar { sidecar_id, .. } = &scope else {
            unreachable!()
        };
        let binding = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
            realm,
            sidecar_id.clone(),
            Some(base.clone()),
            0,
            1,
            0,
            arkret_sdk::sidecar_participant_authority_digest(
                sidecar_id,
                scope.realm_id_opt().unwrap(),
                &controller,
                &[agent.signing_principal_id().clone()],
            )
            .unwrap(),
            vec![id(9)],
        )
        .unwrap();
        let add = sender
            .add_member_with_governance_binding(&package, &binding)
            .unwrap();
        let accepted =
            fixture::accepted_mls_commit_with_binding(agent.clone(), &add.commit, binding, 22);
        let current = arkret_wire::MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: base.clone(),
            cipher_suite: arkret_sdk::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
            current_mls_commit_event_ref: base,
            epoch: 0,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: arkret_sdk::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "33".repeat(32)
            ))
            .unwrap(),
        };
        sender.install_accepted_commit(&accepted, &current).unwrap();
        sender
            .install_test_leaf_bindings(endpoints.clone())
            .unwrap();
        let delivery = fixture::accepted_mls_welcome(
            &add.welcome,
            arkret_sdk::ActorId::account(controller.clone()),
            &accepted,
            1_760_000_000_012,
        );
        let mut receiver = arkret_sdk::ArkretMlsGroup::join_from_verified_welcome_delivery(
            reader, &delivery, &accepted,
        )
        .unwrap();
        receiver.install_test_leaf_bindings(endpoints).unwrap();
        let secure = MemorySecureKeyStore::new();
        let secret =
            crate::mls::runtime::load_or_create_account_mls_secret(&secure, &controller).unwrap();
        let record = receiver.export_state_record().unwrap();
        let checkpoint = crate::mls::persistence::encrypt_state(
            scope.realm_id_opt().unwrap().as_str(),
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            &secret,
            &[62; 16],
        );
        store
            .install_accepted_mls_transition(&scope, checkpoint, &accepted.event.event_id)
            .unwrap();
        let time = "2026-09-22T00:00:00.000Z".parse().unwrap();
        store
            .set_device_authoring_authority(Some(crate::state::PersistedDeviceAuthoringAuthority {
            account_id: controller.clone(),
            device_id: device,
            device_projection: arkret_models_crypto::VerifiedDeviceProjection {
                device_signing_key_did: arkret_sdk::DidKey::new(
                    "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
                )
                .unwrap(),
                hpke_key: arkret_sdk::NonEmptyString::new("hpke-test").unwrap(),
                device_authorize_event_id: id(32),
                authorized_generation_ref: 0,
                device_status: arkret_models_crypto::DeviceStatus::Active,
                authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                    not_before: time,
                    expires_at: None,
                },
                attested_at: time,
                expires_at: "2026-10-22T00:00:00.000Z".parse().unwrap(),
            },
            authoring_generation: crate::identity::authoring_generation::AuthoringGeneration {
                authority_model:
                    crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
                authority_principal_id: controller.principal_id.clone(),
                generation_ref: "generation-0".to_owned(),
            },
        }));
        Self {
            _directory: directory,
            store,
            secure,
            controller,
            scope,
            agent,
            sender,
            state_ref: accepted.event.event_id,
        }
    }

    fn message(
        &mut self,
        body: &[u8],
        proof_seed: [u8; 32],
        position: u64,
    ) -> (Event, EncryptedEnvelope) {
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/json",
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            self.scope.clone(),
            EventKind::MessageCreate.as_str(),
            self.sender.epoch(),
            self.state_ref.clone(),
            self.sender.local_content_sender_domain().unwrap(),
            arkret_sdk::EventContentRoutingContext::None,
        )
        .unwrap();
        let payload = self.sender.encrypt_payload(header, body).unwrap();
        let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(&payload).unwrap();
        let unsigned = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
            EventKind::MessageCreate.as_str(),
            self.scope.clone(),
            self.agent.clone(),
            serde_json::json!({"strand_id":arkret_sdk::StrandId::from_event_id(&id(10)),
                "track_name":"discussion", "encrypted_content":envelope}),
        )
        .build_unsigned()
        .unwrap();
        let mut authored = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
            unsigned,
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
        let signer = crate::event_signer::InksonEventSigner::from_dyn_signer(
            std::sync::Arc::new(
                arkret_sdk::signatures::proof::Ed25519DetachedJwsSigner::new(
                    ed25519_dalek::SigningKey::from_bytes(&proof_seed),
                    AGENT_METHOD.to_owned(),
                ),
            ),
            AGENT_DID.to_owned(),
        );
        signer.sign_envelope(&mut authored).unwrap();
        let event = authored.into_event();
        self.index_signer(&event, position);
        (event, envelope)
    }

    fn index_signer(&mut self, event: &Event, position: u64) {
        let stream_ref = arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .unwrap();
        let target_ref = arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: arkret_sdk::RealmCommitId::from_digest([position as u8; 32]),
            stream_ref: stream_ref.clone(),
            stream_position: position,
        };
        let method = arkret_sdk::DidUrl::new(AGENT_METHOD).unwrap();
        let accepted_at = event.producer_proof.as_ref().unwrap().created_at;
        self.store
            .index_historical_agent_event_candidate(crate::state::HistoricalAgentEventCandidate {
                authority_chain_verified: true,
                recipient_account_id: self.controller.clone(),
                realm_id: event.realm_id.clone(),
                target_ref: target_ref.clone(),
                accepted_event: event.clone(),
                agent_actor_id: self.agent.clone(),
                agent_id: self.agent.signing_principal_id().clone(),
                verification_method: method.clone(),
                receiver_id: self.controller.station_id.clone(),
                indexed_at_unix_ms: position,
            })
            .unwrap();
        self.store
            .store_historical_agent_signer_key(crate::state::CachedHistoricalAgentSignerKey {
                recipient_account_id: self.controller.clone(),
                realm_id: event.realm_id.clone(),
                target_ref,
                receiver_id: self.controller.station_id.clone(),
                accepted_at,
                actor: self.agent.clone(),
                verification_method: method,
                public_key_b64u: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
                    ed25519_dalek::SigningKey::from_bytes(&AGENT_SEED)
                        .verifying_key()
                        .to_bytes(),
                ))
                .unwrap(),
                authorization_ref: arkret_wire::CommittedEventRef {
                    event_id: id(31),
                    commit_id: arkret_sdk::RealmCommitId::from_digest([33; 32]),
                    stream_ref,
                    stream_position: 1,
                },
                revision: arkret_wire::CurrentRevision {
                    commit_id: arkret_sdk::RealmCommitId::from_digest([34; 32]),
                    stream_position: position,
                },
                governance_generation: 0,
                cached_at_unix_ms: position,
            })
            .unwrap();
    }

    fn eligible(
        &self,
        event: &Event,
        envelope: &EncryptedEnvelope,
        cache: &mut FoldValidationCache,
        secure: &MemorySecureKeyStore,
    ) -> anyhow::Result<bool> {
        eligible_agents_with_secure_store(
            &self.store,
            &self.controller,
            event,
            envelope,
            &[self.agent.signing_principal_id().clone()],
            cache,
            secure,
        )
    }
}

#[test]
fn warm_mls_cache_reuses_the_verified_tree_but_checks_each_event_producer() {
    let mut fixture = MlsFixture::new();
    let mut cache = FoldValidationCache::new(&fixture.store);
    let (first, first_envelope) = fixture.message(b"first response", AGENT_SEED, 10);
    assert_eq!(
        decrypt_with_secure_store(
            &fixture.store,
            &fixture.controller,
            &first,
            &first_envelope,
            &mut cache,
            &fixture.secure
        )
        .unwrap(),
        b"first response"
    );
    assert_eq!(cache.agents.len(), 1);
    assert_eq!(cache.authors.len(), 1);
    let empty_secure = MemorySecureKeyStore::new();
    assert!(
        fixture
            .eligible(&first, &first_envelope, &mut cache, &empty_secure)
            .unwrap(),
        "eligibility reuses the exact authenticated Agent group_state without restoring a secret"
    );

    let (second, second_envelope) = fixture.message(b"second response", AGENT_SEED, 11);
    assert_eq!(
        decrypt_with_secure_store(
            &fixture.store,
            &fixture.controller,
            &second,
            &second_envelope,
            &mut cache,
            &fixture.secure
        )
        .unwrap(),
        b"second response"
    );
    assert_eq!(cache.agents.len(), 1);
    assert_eq!(cache.authors.len(), 1);
    assert_eq!(
        decrypt_with_secure_store(
            &fixture.store,
            &fixture.controller,
            &second,
            &second_envelope,
            &mut cache,
            &empty_secure
        )
        .unwrap(),
        b"second response"
    );

    let mut changed = second.clone();
    changed.created_at += chrono::Duration::seconds(1);
    assert!(
        decrypt_with_secure_store(
            &fixture.store,
            &fixture.controller,
            &changed,
            &second_envelope,
            &mut cache,
            &empty_secure
        )
        .is_err(),
        "warm tree and plaintext caches cannot replace each Event's proof/content binding"
    );
    let (forged, forged_envelope) = fixture.message(b"forged response", [99; 32], 12);
    forged
        .validate_proof_bindings_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
        .unwrap();
    let error = decrypt_with_secure_store(
        &fixture.store,
        &fixture.controller,
        &forged,
        &forged_envelope,
        &mut cache,
        &empty_secure,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("historical Agent signer and MLS binding"),
        "{error}"
    );
    assert_eq!(cache.agents.len(), 1);
}

#[test]
fn warm_mls_cache_does_not_borrow_another_epoch_state_reference_or_scope() {
    let mut fixture = MlsFixture::new();
    let (event, envelope) = fixture.message(b"private response", AGENT_SEED, 10);
    let mut cache = FoldValidationCache::new(&fixture.store);
    assert!(
        fixture
            .eligible(&event, &envelope, &mut cache, &fixture.secure)
            .unwrap()
    );
    assert_eq!(cache.authors.len(), 1);

    let mut wrong_epoch = serde_json::to_value(&envelope).unwrap();
    wrong_epoch["encryption_context"]["epoch"] = serde_json::json!(fixture.sender.epoch() + 1);
    let wrong_epoch: EncryptedEnvelope = serde_json::from_value(wrong_epoch).unwrap();
    assert!(
        fixture
            .eligible(&event, &wrong_epoch, &mut cache, &fixture.secure)
            .is_err()
    );
    let mut wrong_ref = serde_json::to_value(&envelope).unwrap();
    wrong_ref["encryption_context"]["group_state_ref"] = serde_json::json!(id(91));
    let wrong_ref: EncryptedEnvelope = serde_json::from_value(wrong_ref).unwrap();
    assert!(
        fixture
            .eligible(&event, &wrong_ref, &mut cache, &fixture.secure)
            .is_err()
    );

    let mut other_sidecar = event.clone();
    other_sidecar.scope_ref = ScopeRef::Sidecar {
        realm_id: event.realm_id.clone(),
        sidecar_id: arkret_sdk::SidecarId::from_event_id(&id(92)),
    };
    assert!(
        fixture
            .eligible(&other_sidecar, &envelope, &mut cache, &fixture.secure)
            .is_err()
    );
    let mut other_realm = other_sidecar.clone();
    other_realm.realm_id = arkret_sdk::RealmId::from_event_id(&id(93));
    other_realm.scope_ref = ScopeRef::Sidecar {
        realm_id: other_realm.realm_id.clone(),
        sidecar_id: arkret_sdk::SidecarId::from_event_id(&id(9)),
    };
    assert!(
        fixture
            .eligible(&other_realm, &envelope, &mut cache, &fixture.secure)
            .is_err()
    );
    let mut realm_scope = event.clone();
    realm_scope.scope_ref = ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    assert!(
        fixture
            .eligible(&realm_scope, &envelope, &mut cache, &fixture.secure)
            .is_err()
    );
    assert_eq!(
        cache.authors.len(),
        1,
        "failed coordinates must never populate a verified view"
    );

    assert_eq!(
        decrypt_with_secure_store(
            &fixture.store,
            &fixture.controller,
            &event,
            &envelope,
            &mut cache,
            &fixture.secure
        )
        .unwrap(),
        b"private response"
    );
    assert_eq!(cache.agents.len(), 1);
    assert!(
        fixture
            .eligible(&event, &envelope, &mut cache, &MemorySecureKeyStore::new())
            .unwrap()
    );
    let mut fresh_fold = FoldValidationCache::new(&fixture.store);
    assert!(
        fixture
            .eligible(
                &event,
                &envelope,
                &mut fresh_fold,
                &MemorySecureKeyStore::new()
            )
            .is_err(),
        "the verified tree is not retained across fold lifetimes"
    );
    assert!(fresh_fold.authors.is_empty());
}
