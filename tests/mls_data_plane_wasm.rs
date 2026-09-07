#![cfg(target_arch = "wasm32")]

//! Browser-side MLS data-plane behaviour: the SDK's MLS group primitives must
//! keep their epoch/membership semantics when compiled to `wasm32`, and the
//! four "cannot decrypt" outcomes must stay distinguishable.
//!
//! The `LocalMlsDevice` harness below lives in this test binary on purpose.
//! Inkson's product paths drive MLS through `src/mls/runtime`, which owns
//! device snapshots, the secure key store and the local state store; a bare
//! in-memory device pair exists only to pin the SDK primitives, so it must not
//! ship inside the library.

use arkret_sdk::{
    ArkretMlsGroup, ArkretMlsIdentity, DeviceId, EncryptedMessage, EncryptedPayload, MessageCrypto,
    MessageCryptoDecrypt, MessageCryptoUnavailable, MlsAddMemberResult, MlsCommitEnvelope,
    MlsKeyPackageRecord, MlsProposalEnvelope, MlsRemoveMemberResult, MlsWelcomeEnvelope,
};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientEncryptedMessage {
    message_id: String,
    payload: EncryptedPayload,
}

/// Minimal in-memory MLS device: one identity that either creates or joins a
/// single group, then encrypts/decrypts application messages on it.
struct LocalMlsDevice {
    identity: Option<ArkretMlsIdentity>,
    group: Option<ArkretMlsGroup>,
}

fn principal_core_id(principal_did: &str) -> anyhow::Result<arkret_sdk::DidCoreId> {
    let did = arkret_sdk::Did::new(principal_did.trim().to_owned())?;
    arkret_sdk::project_did_to_core_id(&did).map_err(anyhow::Error::msg)
}

impl LocalMlsDevice {
    fn new(principal_id: &str, device_id: &str) -> anyhow::Result<Self> {
        Ok(Self {
            identity: Some(ArkretMlsIdentity::new_test_human_device(
                principal_core_id(principal_id)?,
                DeviceId::new(device_id.to_owned())?,
            )?),
            group: None,
        })
    }

    fn key_package_record(&self) -> anyhow::Result<MlsKeyPackageRecord> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MLS identity is already bound to a group"))?;
        Ok(identity.key_package_record()?)
    }

    fn create_group(&mut self, group_id: impl AsRef<[u8]>) -> anyhow::Result<()> {
        let identity = self
            .identity
            .take()
            .ok_or_else(|| anyhow::anyhow!("MLS group already created or joined"))?;
        self.group = Some(identity.create_group(group_id)?);
        Ok(())
    }

    fn join_from_welcome(&mut self, welcome: &MlsWelcomeEnvelope) -> anyhow::Result<()> {
        let identity = self
            .identity
            .take()
            .ok_or_else(|| anyhow::anyhow!("MLS group already created or joined"))?;
        self.group = Some(ArkretMlsGroup::join_from_welcome(identity, welcome)?);
        Ok(())
    }

    fn add_member(
        &mut self,
        member_key_package: &MlsKeyPackageRecord,
    ) -> anyhow::Result<MlsAddMemberResult> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
        Ok(group.add_member(member_key_package)?)
    }

    /// Install this in-memory fixture's transition bindings from its author.
    /// Product code obtains these bindings from verified governance evidence.
    fn install_fixture_bindings_from(&mut self, author: &Self) -> anyhow::Result<()> {
        let bindings = author.group.as_ref().unwrap().verified_leaf_bindings()?;
        self.group
            .as_mut()
            .unwrap()
            .install_verified_leaf_bindings(bindings)?;
        Ok(())
    }

    fn actor_id(&self) -> anyhow::Result<arkret_sdk::ActorId> {
        let group = self
            .group
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
        let endpoint = group.identity().endpoint_identity();
        group
            .verified_leaf_bindings()?
            .into_iter()
            .find(|binding| binding.endpoint == endpoint)
            .map(|binding| binding.actor_id)
            .ok_or_else(|| anyhow::anyhow!("local endpoint has no verified actor binding"))
    }

    /// Remove a complete verified actor, advancing the local MLS epoch. The
    /// returned result carries the commit envelope; surviving members must
    /// apply it (via `apply_commit`) to converge.
    fn remove_member_by_actor(
        &mut self,
        target: &arkret_sdk::ActorId,
    ) -> anyhow::Result<MlsRemoveMemberResult> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
        Ok(group.remove_members_by_actor(std::slice::from_ref(target))?)
    }

    fn apply_commit(&mut self, commit: &MlsCommitEnvelope) -> anyhow::Result<u64> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
        Ok(group.apply_commit(commit)?)
    }

    /// Stage a by-reference MLS proposal (e.g. one carried in
    /// `MlsRemoveMemberResult::proposals`) so a subsequent `apply_commit` that
    /// references it can converge. Surviving members MUST apply every proposal
    /// a commit references before applying the commit itself, including Add
    /// proposals delivered separately from their commit.
    fn apply_proposal(&mut self, proposal: &MlsProposalEnvelope) -> anyhow::Result<()> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
        Ok(group.apply_proposal(proposal)?)
    }

    fn encrypt_message(
        &mut self,
        message_id: impl Into<String>,
        plaintext: &[u8],
    ) -> anyhow::Result<ClientEncryptedMessage> {
        let message_id = message_id.into();
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/vnd.arkret.message+json",
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(std::str::from_utf8(GROUP_ID)?.to_owned())?,
            },
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            group.epoch(),
            arkret_sdk::EventId::new(
                "ak:event:ARKEyrg59dN-i97Pleo3vwwRkZomIcqPiuK9PtjzGLdh".to_owned(),
            )?,
            group.local_content_sender_domain()?,
            None,
            arkret_sdk::EventContentRoutingContext::None,
        )?;
        let encrypted = MessageCrypto::encrypt(group, message_id, header, plaintext)?;
        Ok(ClientEncryptedMessage {
            message_id: encrypted.message_id,
            payload: encrypted.payload,
        })
    }

    fn decrypt_or_preserve(
        &mut self,
        message: ClientEncryptedMessage,
    ) -> anyhow::Result<MessageCryptoDecrypt> {
        Ok(MessageCrypto::decrypt_or_preserve(
            self.group.as_mut(),
            EncryptedMessage {
                message_id: message.message_id,
                payload: message.payload,
            },
        )?)
    }
}

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000002";
const CAROL_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000003";
const DAVE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000004";
const GROUP_ID: &[u8] = b"ak:realm:Abv-DTiqqItOdVuCsiERm9HxIf_JwLqRfx9WfkG_eVld";

#[wasm_bindgen_test]
fn removed_member_cannot_decrypt_new_epoch_and_failures_are_distinct() {
    let mut alice = LocalMlsDevice::new("did:web:alice.example", ALICE_DEVICE).unwrap();
    let mut bob = LocalMlsDevice::new("did:web:bob.example", BOB_DEVICE).unwrap();
    let mut carol = LocalMlsDevice::new("did:web:carol.example", CAROL_DEVICE).unwrap();

    alice.create_group(GROUP_ID).unwrap();
    let add_bob = alice
        .add_member(&bob.key_package_record().unwrap())
        .unwrap();
    bob.join_from_welcome(&add_bob.welcome).unwrap();
    bob.install_fixture_bindings_from(&alice).unwrap();
    let add_carol = alice
        .add_member(&carol.key_package_record().unwrap())
        .unwrap();
    bob.apply_proposal(&add_carol.proposal).unwrap();
    bob.apply_commit(&add_carol.commit).unwrap();
    carol.join_from_welcome(&add_carol.welcome).unwrap();
    bob.install_fixture_bindings_from(&alice).unwrap();
    carol.install_fixture_bindings_from(&alice).unwrap();

    let pre_remove = alice
        .encrypt_message(
            "ak:message:A6u77rrmwcqnlGOsjJ1NCtyWmSQNe4IqYUz4mjELtyso",
            b"before remove",
        )
        .unwrap();
    assert!(matches!(
        bob.decrypt_or_preserve(pre_remove).unwrap(),
        MessageCryptoDecrypt::Plaintext { .. }
    ));

    let bob_actor = bob.actor_id().unwrap();
    let remove = alice.remove_member_by_actor(&bob_actor).unwrap();
    for proposal in &remove.proposals {
        bob.apply_proposal(proposal).unwrap();
        carol.apply_proposal(proposal).unwrap();
    }
    bob.apply_commit(&remove.commit).unwrap();
    carol.apply_commit(&remove.commit).unwrap();
    carol.install_fixture_bindings_from(&alice).unwrap();

    let post_remove = alice
        .encrypt_message(
            "ak:message:AQKPg68zbJImnDqlj1CYc3otm32z4cR6NCjKfy5qS5xU",
            b"after remove",
        )
        .unwrap();
    assert!(matches!(
        carol.decrypt_or_preserve(post_remove.clone()).unwrap(),
        MessageCryptoDecrypt::Plaintext { .. }
    ));
    assert!(matches!(
        bob.decrypt_or_preserve(post_remove.clone()).unwrap(),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::Removed,
            ..
        }
    ));

    let mut never_joined = LocalMlsDevice::new("did:web:never.example", DAVE_DEVICE).unwrap();
    assert!(matches!(
        never_joined
            .decrypt_or_preserve(post_remove.clone())
            .unwrap(),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::NoSession,
            ..
        }
    ));

    let mut independent = LocalMlsDevice::new("did:web:dave.example", DAVE_DEVICE).unwrap();
    independent.create_group(GROUP_ID).unwrap();
    let wrong_key = independent
        .encrypt_message(
            "ak:message:AxNcKZEEPR7EFcSKxQ_Lptlgx8iJpZeZqrrfTAafbPbw",
            b"wrong key",
        )
        .unwrap();
    assert!(matches!(
        carol.decrypt_or_preserve(wrong_key).unwrap(),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::KeyUnavailable(_),
            ..
        }
    ));

    let mut damaged = post_remove;
    damaged.payload.ciphertext.push('A');
    assert!(carol.decrypt_or_preserve(damaged).is_err());
}
