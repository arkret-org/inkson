#![cfg(target_arch = "wasm32")]

//! Browser-side MLS data-plane behaviour: the SDK's MLS group primitives must
//! keep their epoch/membership semantics when compiled to `wasm32`, and the
//! four "cannot decrypt" outcomes must stay distinguishable.
//!
//! Every membership change follows the current v1 lifecycle: the Add or
//! Remove proposal is inline in one Commit bound to the next-epoch governance
//! binding, the Commit is installed only as an accepted `ak.mls.commit` Event
//! with its `RealmCommit` against the exact pre-transition `MlsGroupCurrent`,
//! and a new member joins only from an `MlsWelcomeDelivery` naming that
//! accepted Commit.
//!
//! The `LocalMlsDevice` harness lives in this test binary on purpose. Inkson's
//! product paths drive MLS through `src/mls/runtime`, which owns device
//! snapshots, the secure key store and the local state store; a bare in-memory
//! device exists only to pin the SDK primitives, so it must not ship inside
//! the library. Producer-proof and RealmCommit signatures are outside this
//! harness: the SDK consumers take already verified accepted carriers.

use arkret_sdk::{
    ArkretMlsGroup, ArkretMlsIdentity, CommittedEventFullView, DeviceId, EncryptedMessage,
    EncryptedPayload, EventId, MessageCrypto, MessageCryptoDecrypt, MessageCryptoUnavailable,
    MlsAddMemberResult, MlsCommitEnvelope, MlsGovernanceBindingPayload, MlsKeyPackageRecord,
    MlsRemoveMemberResult, MlsWelcomeDelivery, MlsWelcomeDraft, ScopeRef,
};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000002";
const CAROL_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000003";
const DAVE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000004";
const REALM: &str = "ak:realm:Abv-DTiqqItOdVuCsiERm9HxIf_JwLqRfx9WfkG_eVld";
const STATION: &str = "ak:did_core:web:wasm-test-station.example";

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientEncryptedMessage {
    message_id: String,
    payload: EncryptedPayload,
}

fn scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
    }
}

fn actor(principal_did: &str) -> arkret_sdk::ActorId {
    let did = arkret_sdk::Did::new(principal_did.to_owned()).unwrap();
    arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        arkret_sdk::project_did_to_core_id(&did).unwrap(),
        arkret_sdk::DidCoreId::new(STATION.to_owned()).unwrap(),
    ))
}

fn detached_signature(
    context: arkret_sdk::DetachedSignatureContext,
    seed: u8,
) -> arkret_sdk::DetachedObjectSignature {
    arkret_sdk::DetachedObjectSignature {
        context,
        signature_algorithm: arkret_sdk::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_sdk::DidUrl::new("did:web:station.example#key-1").unwrap(),
        signed_digest: arkret_sdk::Hash::new(format!(
            "sha256:{}",
            format!("{seed:02x}").repeat(32)
        ))
        .unwrap(),
        created_at: "2026-09-26T00:00:00.000Z".parse().unwrap(),
        sig: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode([seed; 64])).unwrap(),
    }
}

/// The Station's public MLS state of the scope, as its `mls_group` current.
#[derive(Clone)]
struct AcceptedGroupState {
    genesis_event_ref: EventId,
    current_event_ref: EventId,
    epoch: u64,
}

impl AcceptedGroupState {
    fn genesis() -> Self {
        let genesis = EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x51; 32]);
        Self {
            genesis_event_ref: genesis.clone(),
            current_event_ref: genesis,
            epoch: 0,
        }
    }

    fn current(&self) -> arkret_wire::MlsGroupCurrent {
        arkret_wire::MlsGroupCurrent {
            effective_scope: scope(),
            genesis_event_ref: self.genesis_event_ref.clone(),
            cipher_suite: arkret_wire::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
            current_mls_commit_event_ref: self.current_event_ref.clone(),
            epoch: self.epoch,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: arkret_sdk::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "33".repeat(32)
            ))
            .unwrap(),
        }
    }

    /// The governance binding the next Commit must carry.
    fn next_binding(&self) -> MlsGovernanceBindingPayload {
        MlsGovernanceBindingPayload::new(
            scope(),
            Some(self.current_event_ref.clone()),
            self.epoch,
            self.epoch + 1,
            0,
        )
        .unwrap()
    }

    /// Wrap an SDK Commit envelope as the accepted `ak.mls.commit` Event and
    /// its `RealmCommit`, then advance the public state past it.
    fn accept(
        &mut self,
        author: arkret_sdk::ActorId,
        envelope: &MlsCommitEnvelope,
    ) -> CommittedEventFullView {
        assert_eq!(envelope.epoch, self.epoch + 1);
        let payload = arkret_sdk::MlsCommitPayload::new(
            self.current_event_ref.clone(),
            0,
            envelope,
            self.next_binding(),
        )
        .unwrap();
        let event = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::MlsCommit>::new(
            scope(),
            author,
            payload,
        )
        .unwrap()
        .author_with_digest_suite(
            "2026-09-26T00:00:00.000Z".parse().unwrap(),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap()
        .into_event();
        let realm_id = arkret_sdk::RealmId::new(REALM.to_owned()).unwrap();
        let seed = 0x60 + u8::try_from(envelope.epoch).unwrap();
        let commit = arkret_sdk::RealmCommit {
            commit_id: arkret_sdk::RealmCommitId::from_digest([seed; 32]),
            realm_id: realm_id.clone(),
            stream_ref: arkret_sdk::CommitStreamRef::from_scope(&scope(), Some(realm_id)).unwrap(),
            stream_position: envelope.epoch,
            previous_commit_ref: Some(arkret_sdk::RealmCommitId::from_digest([seed - 1; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_sdk::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                self.current_event_ref.clone(),
            ),
            committed_at: "2026-09-26T00:00:01.000Z".parse().unwrap(),
            signature: detached_signature(arkret_sdk::DetachedSignatureContext::RealmCommit, seed),
        };
        let accepted = CommittedEventFullView { commit, event };
        accepted.validate_shape().unwrap();
        self.current_event_ref = accepted.event.event_id.clone();
        self.epoch = envelope.epoch;
        accepted
    }
}

/// Bind an SDK Welcome draft to the exact accepted Commit it accompanies.
fn welcome_delivery(
    draft: &MlsWelcomeDraft,
    recipient: arkret_sdk::ActorId,
    accepted: &CommittedEventFullView,
    delivery_time_ms: u64,
) -> MlsWelcomeDelivery {
    let arkret_sdk::MlsEndpointIdentity::HumanDevice { device_id, .. } = &draft.recipient else {
        panic!("the harness only admits human device endpoints");
    };
    let delivery = MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new_v7_at(delivery_time_ms),
        realm_id: accepted.event.realm_id.clone(),
        effective_scope: accepted.event.scope_ref.clone(),
        commit_event_ref: accepted.event.event_id.clone(),
        recipient_actor_id: recipient,
        recipient_endpoint: arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
            device_id: device_id.clone(),
        },
        keypackage_claim_ref: draft.keypackage_claim_ref.clone(),
        ciphertext_b64: draft.ciphertext_b64.clone(),
        producer_proof: detached_signature(
            arkret_sdk::DetachedSignatureContext::MlsWelcomeDelivery,
            0x77,
        ),
    };
    delivery.validate_shape().unwrap();
    delivery
}

/// Minimal in-memory MLS device: one identity that either creates or joins a
/// single group, then encrypts/decrypts application messages on it.
struct LocalMlsDevice {
    actor: arkret_sdk::ActorId,
    endpoint: arkret_sdk::MlsEndpointIdentity,
    identity: Option<ArkretMlsIdentity>,
    group: Option<ArkretMlsGroup>,
}

impl LocalMlsDevice {
    fn new(principal_did: &str, device_id: &str) -> Self {
        let actor = actor(principal_did);
        let identity = ArkretMlsIdentity::new_test_human_device(
            actor.clone(),
            DeviceId::new(device_id.to_owned()).unwrap(),
        )
        .unwrap();
        Self {
            endpoint: identity.endpoint_identity(),
            identity: Some(identity),
            actor,
            group: None,
        }
    }

    /// The device's KeyPackage as the owner Station hands it out after a
    /// claim: the Welcome names that claim.
    fn claimed_key_package(&self, claimed_at_ms: u64) -> MlsKeyPackageRecord {
        let mut record = self
            .identity
            .as_ref()
            .expect("MLS identity is already bound to a group")
            .key_package_record()
            .unwrap();
        record.state = arkret_sdk::MlsKeyPackageState::Claimed;
        record.claim_id =
            Some(arkret_wire::KeypackageClaimId::new_v7_at(claimed_at_ms).to_string());
        record
    }

    fn create_group(&mut self) {
        let identity = self.identity.take().expect("MLS group already bound");
        self.group = Some(identity.create_group(&scope()).unwrap());
    }

    fn join(&mut self, delivery: &MlsWelcomeDelivery, accepted: &CommittedEventFullView) {
        let identity = self.identity.take().expect("MLS group already bound");
        self.group = Some(
            ArkretMlsGroup::join_from_verified_welcome_delivery(identity, delivery, accepted)
                .unwrap(),
        );
    }

    fn group(&mut self) -> &mut ArkretMlsGroup {
        self.group.as_mut().expect("MLS group is not available")
    }

    fn add_member(
        &mut self,
        member_key_package: &MlsKeyPackageRecord,
        state: &AcceptedGroupState,
    ) -> MlsAddMemberResult {
        let binding = state.next_binding();
        self.group()
            .add_member_with_governance_binding(member_key_package, &binding)
            .unwrap()
    }

    fn remove_member(
        &mut self,
        target: &arkret_sdk::ActorId,
        state: &AcceptedGroupState,
    ) -> MlsRemoveMemberResult {
        let binding = state.next_binding();
        self.group()
            .remove_members_by_actor_with_governance_binding(std::slice::from_ref(target), &binding)
            .unwrap()
    }

    /// Install an accepted Commit against the exact pre-transition current.
    fn install(
        &mut self,
        accepted: &CommittedEventFullView,
        base: &arkret_wire::MlsGroupCurrent,
    ) -> u64 {
        self.group()
            .install_accepted_commit(accepted, base)
            .unwrap()
    }

    /// Install the post-transition leaf bindings of the current roster.
    /// Product code derives them from verified governance evidence; this
    /// harness names the member endpoints directly.
    fn install_fixture_bindings(&mut self, roster: &[&arkret_sdk::MlsEndpointIdentity]) {
        self.group()
            .install_test_leaf_bindings(roster.iter().map(|endpoint| (*endpoint).clone()).collect())
            .unwrap();
    }

    fn encrypt_message(&mut self, message_id: &str, plaintext: &[u8]) -> ClientEncryptedMessage {
        let group = self.group();
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/vnd.arkret.message+json",
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            scope(),
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            group.epoch(),
            EventId::new("ak:event:ARKEyrg59dN-i97Pleo3vwwRkZomIcqPiuK9PtjzGLdh".to_owned())
                .unwrap(),
            group.local_content_sender_domain().unwrap(),
            arkret_sdk::EventContentRoutingContext::None,
        )
        .unwrap();
        let encrypted = MessageCrypto::encrypt(group, message_id, header, plaintext).unwrap();
        ClientEncryptedMessage {
            message_id: encrypted.message_id,
            payload: encrypted.payload,
        }
    }

    fn decrypt_or_preserve(&mut self, message: ClientEncryptedMessage) -> MessageCryptoDecrypt {
        MessageCrypto::decrypt_or_preserve(
            self.group.as_mut(),
            EncryptedMessage {
                message_id: message.message_id,
                payload: message.payload,
            },
        )
        .unwrap()
    }
}

#[wasm_bindgen_test]
fn removed_member_cannot_decrypt_new_epoch_and_failures_are_distinct() {
    let mut alice = LocalMlsDevice::new("did:web:alice.example", ALICE_DEVICE);
    let mut bob = LocalMlsDevice::new("did:web:bob.example", BOB_DEVICE);
    let mut carol = LocalMlsDevice::new("did:web:carol.example", CAROL_DEVICE);
    let mut state = AcceptedGroupState::genesis();

    alice.create_group();
    let alice_endpoint = alice.endpoint.clone();
    let bob_endpoint = bob.endpoint.clone();
    let carol_endpoint = carol.endpoint.clone();
    alice.install_fixture_bindings(&[&alice_endpoint]);

    // Add Bob: one inline Add Commit, accepted, then Bob's Welcome.
    let base = state.current();
    let add_bob = alice.add_member(&bob.claimed_key_package(1_790_000_000_001), &state);
    let accepted_add_bob = state.accept(alice.actor.clone(), &add_bob.commit);
    assert_eq!(alice.install(&accepted_add_bob, &base), 1);
    let bob_welcome = welcome_delivery(
        &add_bob.welcome,
        bob.actor.clone(),
        &accepted_add_bob,
        1_790_000_000_002,
    );
    bob.join(&bob_welcome, &accepted_add_bob);
    for member in [&mut alice, &mut bob] {
        member.install_fixture_bindings(&[&alice_endpoint, &bob_endpoint]);
    }
    assert_eq!(bob.group().epoch(), 1);

    // Add Carol: existing members install the accepted Commit; the proposal
    // travels inline, so there is nothing to stage separately.
    let base = state.current();
    let add_carol = alice.add_member(&carol.claimed_key_package(1_790_000_000_003), &state);
    let accepted_add_carol = state.accept(alice.actor.clone(), &add_carol.commit);
    assert_eq!(alice.install(&accepted_add_carol, &base), 2);
    assert_eq!(bob.install(&accepted_add_carol, &base), 2);
    let carol_welcome = welcome_delivery(
        &add_carol.welcome,
        carol.actor.clone(),
        &accepted_add_carol,
        1_790_000_000_004,
    );
    // A Welcome naming a Commit other than the accepted one is refused before
    // it can create a group.
    let stray = LocalMlsDevice::new("did:web:carol.example", CAROL_DEVICE);
    assert!(
        ArkretMlsGroup::join_from_verified_welcome_delivery(
            stray.identity.unwrap(),
            &carol_welcome,
            &accepted_add_bob,
        )
        .is_err()
    );
    carol.join(&carol_welcome, &accepted_add_carol);
    for member in [&mut alice, &mut bob, &mut carol] {
        member.install_fixture_bindings(&[&alice_endpoint, &bob_endpoint, &carol_endpoint]);
    }

    let pre_remove = alice.encrypt_message(
        "ak:message:A6u77rrmwcqnlGOsjJ1NCtyWmSQNe4IqYUz4mjELtyso",
        b"before remove",
    );
    assert!(matches!(
        bob.decrypt_or_preserve(pre_remove),
        MessageCryptoDecrypt::Plaintext { .. }
    ));

    // Remove Bob: one inline Remove Commit installed by every member.
    let base = state.current();
    let bob_actor = bob.actor.clone();
    let remove = alice.remove_member(&bob_actor, &state);
    assert_eq!(remove.removed_actors, vec![bob_actor]);
    let accepted_remove = state.accept(alice.actor.clone(), &remove.commit);
    assert_eq!(alice.install(&accepted_remove, &base), 3);
    assert_eq!(carol.install(&accepted_remove, &base), 3);
    bob.install(&accepted_remove, &base);
    assert!(!bob.group().is_active());
    for member in [&mut alice, &mut carol] {
        member.install_fixture_bindings(&[&alice_endpoint, &carol_endpoint]);
    }

    let post_remove = alice.encrypt_message(
        "ak:message:AQKPg68zbJImnDqlj1CYc3otm32z4cR6NCjKfy5qS5xU",
        b"after remove",
    );
    assert!(matches!(
        carol.decrypt_or_preserve(post_remove.clone()),
        MessageCryptoDecrypt::Plaintext { ref plaintext, .. } if plaintext == b"after remove"
    ));
    assert!(matches!(
        bob.decrypt_or_preserve(post_remove.clone()),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::Removed,
            ..
        }
    ));

    let mut never_joined = LocalMlsDevice::new("did:web:never.example", DAVE_DEVICE);
    assert!(matches!(
        never_joined.decrypt_or_preserve(post_remove.clone()),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::NoSession,
            ..
        }
    ));

    let mut independent = LocalMlsDevice::new("did:web:dave.example", DAVE_DEVICE);
    independent.create_group();
    let wrong_key = independent.encrypt_message(
        "ak:message:AxNcKZEEPR7EFcSKxQ_Lptlgx8iJpZeZqrrfTAafbPbw",
        b"wrong key",
    );
    assert!(matches!(
        carol.decrypt_or_preserve(wrong_key),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::KeyUnavailable(_),
            ..
        }
    ));

    let mut damaged = post_remove;
    damaged.payload.ciphertext.push('A');
    assert!(
        MessageCrypto::decrypt_or_preserve(
            carol.group.as_mut(),
            EncryptedMessage {
                message_id: damaged.message_id,
                payload: damaged.payload,
            },
        )
        .is_err()
    );
}
