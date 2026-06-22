use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::Signer;
use serde_json::{Value, json};

use crate::cross_signing::{CrossSigningKeyRole, load_signing_key};
use crate::local_state::LocalStateStore;
use crate::mls::persistence::MlsSnapshotEnvelope;
use crate::operation::trim_realm_id;
use crate::secure_key_store::SecureKeyStore;

pub(crate) const CROSS_SIGNING_PUBLISH_LATEST_KEY: &str = "cross_signing.publish.latest";

pub(crate) struct RealmMlsAdmissionEvents {
    pub(crate) commit: cokret_sdk::Event,
    pub(crate) welcome: cokret_sdk::Event,
    #[cfg(test)]
    pub(crate) welcome_envelope: cokret_sdk::MlsWelcomeEnvelope,
    pub(crate) snapshot: MlsSnapshotEnvelope,
}

pub(crate) fn build_realm_mls_admission_events_from_claim(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    claim: &cokret_sdk::KeypackageClaimRecord,
    claim_nonce: &str,
) -> Result<RealmMlsAdmissionEvents, String> {
    let member_key_package = crate::api::keypackage_claim_record_to_mls_record(claim)
        .map_err(|err| format!("MLS KeyPackage claim decode failed: {err}"))?;
    let (add, snapshot) = crate::mls::runtime::build_add_member_commit_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        actor_id,
        device_id,
        &member_key_package,
    )
    .map_err(|err| err.user_message())?;
    let commit = crate::views::kanban::kanban_mls_commit_event_from_store_for_effective_scope(
        state_store,
        realm_id,
        None,
        actor_id,
        &add.commit,
    )?;
    let governance_binding = commit
        .content
        .get("governance_binding")
        .cloned()
        .ok_or_else(|| "MLS commit event missing governance_binding".to_owned())?;
    let welcome_payload = build_mls_welcome_payload_value(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
        claim,
        &member_key_package.keypackage_id,
        &add,
        &commit,
        governance_binding,
        claim_nonce,
    )?;
    let welcome = crate::operation::ck_ops::mls_welcome_with_governance(
        realm_id,
        actor_id,
        &add.welcome.group_id,
        &welcome_payload,
    )
    .build_sdk_event("yougen")
    .map_err(|err| format!("MLS Welcome SDK Event conversion failed: {err}"))?;
    Ok(RealmMlsAdmissionEvents {
        commit,
        welcome,
        #[cfg(test)]
        welcome_envelope: add.welcome.clone(),
        snapshot,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_mls_welcome_payload_value(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    sender_device_id: &str,
    claim: &cokret_sdk::KeypackageClaimRecord,
    _key_package_id: &str,
    add: &cokret_sdk::MlsAddMemberResult,
    commit_event: &cokret_sdk::Event,
    governance_binding: Value,
    claim_nonce: &str,
) -> Result<Value, String> {
    let intended_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS Welcome Realm id: {err:?}"))?;
    let requester_did = cokret_sdk::Did::new(actor_id.trim().to_owned())
        .map_err(|err| format!("invalid MLS Welcome requester DID: {err:?}"))?;
    let mut envelope = cokret_sdk::MlsWelcomeClaimEnvelope {
        keypackage_ref: claim.keypackage_ref.clone(),
        keypackage_digest: claim.keypackage_digest.clone(),
        intended_realm_id,
        claim_id: claim.claim_id.clone(),
        requester_did,
        ssk_generation: claim.ssk_generation,
        nonce: claim_nonce.trim().to_owned(),
        welcome_digest: add.welcome.welcome_hash.clone(),
        created_at: crate::clock::now_utc(),
        signature: cokret_sdk::Signature2 {
            kid: String::new(),
            alg: Some("EdDSA".to_owned()),
            sig: String::new(),
        },
    };
    sign_welcome_claim_envelope(state_store, secure_store, actor_id, &mut envelope)?;
    let claim_ref = cokret_sdk::MlsWelcomePayloadClaimRef {
        claim_id: claim.claim_id.clone(),
        keypackage_ref: claim.keypackage_ref.clone(),
        keypackage_digest: claim.keypackage_digest.clone(),
        capabilities_digest: claim.capabilities_digest.clone(),
        ssk_generation: claim.ssk_generation,
    };
    let commit_ref = commit_event.event_id.as_str().to_owned();
    Ok(json!({
        "mls_group_id": add.welcome.group_id,
        "epoch": add.welcome.epoch,
        "recipient_principal_id": claim.principal_id,
        "recipient_device_id": claim.device_id,
        "sender_device_id": sender_device_id,
        "keypackage_ref": claim.keypackage_ref,
        "keypackage_digest": claim.keypackage_digest,
        "claim_id": claim.claim_id,
        "claim_ref": claim_ref,
        "claim_envelope": envelope,
        "ciphertext": add.welcome.welcome,
        "commit_ref": commit_ref,
        "governance_binding": governance_binding,
        "expires_at": claim.expires_at,
    }))
}

fn sign_welcome_claim_envelope(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    actor_id: &str,
    envelope: &mut cokret_sdk::MlsWelcomeClaimEnvelope,
) -> Result<(), String> {
    let publish = load_latest_cross_signing_publish(state_store, actor_id)?;
    if publish.generation != envelope.ssk_generation {
        return Err(format!(
            "MLS Welcome claim SSK generation {} does not match local cross-signing generation {}",
            envelope.ssk_generation, publish.generation
        ));
    }
    let signing_key = load_signing_key(
        secure_store,
        actor_id,
        publish.generation,
        CrossSigningKeyRole::SelfSigning,
    )
    .map_err(|err| format!("load self-signing key: {err}"))?
    .ok_or_else(|| "self-signing key is not available on this device".to_owned())?;
    envelope.signature.kid = publish.self_signing_key.key.kid.clone();
    let signing_bytes = envelope
        .canonical_signing_bytes()
        .map_err(|err| format!("MLS Welcome claim canonical bytes: {err}"))?;
    let signature = signing_key.sign(&signing_bytes);
    envelope.signature.sig = STANDARD_NO_PAD.encode(signature.to_bytes());
    Ok(())
}

fn load_latest_cross_signing_publish(
    state_store: &LocalStateStore,
    actor_id: &str,
) -> Result<cokret_sdk::CrossSigningPublishContent, String> {
    let Some(raw) = state_store.load_private_data(actor_id, CROSS_SIGNING_PUBLISH_LATEST_KEY)
    else {
        return Err("cross-signing publish state is not available on this device".to_owned());
    };
    serde_json::from_str(&raw).map_err(|err| format!("cross-signing publish state decode: {err}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::cross_signing::{CrossSigningExecutor, CrossSigningSetupPlan};
    use crate::local_state::isolated_store_for_tests;
    use crate::mls::runtime::{
        apply_welcome_messages_with_device_snapshot, ensure_creator_mls_snapshot,
        store_mls_key_package_identity_state,
    };
    use crate::secure_key_store::MemorySecureKeyStore;

    fn install_cross_signing(
        state: &mut LocalStateStore,
        secure: &MemorySecureKeyStore,
        actor: &str,
        device: &str,
    ) -> cokret_sdk::CrossSigningPublishContent {
        let plan = CrossSigningSetupPlan::build_initial(actor, device);
        let principal = cokret_sdk::Did::new(actor.to_owned()).unwrap();
        let trust_domain =
            cokret_sdk::TypedTrustDomainId::new("ck:trust_domain:example.test").unwrap();
        let output = CrossSigningExecutor::new(plan, principal, trust_domain)
            .run()
            .unwrap();
        output.persist_private_keys(secure, actor).unwrap();
        state.save_private_data(
            actor,
            CROSS_SIGNING_PUBLISH_LATEST_KEY,
            serde_json::to_string(&output.publish_content).unwrap(),
        );
        output.publish_content
    }

    fn claim_from_key_package(
        record: &cokret_sdk::MlsKeyPackageRecord,
        ssk_generation: u64,
    ) -> cokret_sdk::KeypackageClaimRecord {
        cokret_sdk::KeypackageClaimRecord {
            claim_id: "ck:mls_keypackage:test:Y2xhaW0tbm9uY2U".to_owned(),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            keypackage_digest: record.keypackage_ref.clone(),
            principal_id: record.principal_id.clone(),
            device_id: record.device_id.as_str().to_owned(),
            key_package: record.key_package.clone(),
            capabilities: record.capabilities.clone(),
            capabilities_digest: record.keypackage_ref.clone(),
            ssk_generation,
            expires_at: crate::clock::now_utc() + chrono::Duration::hours(1),
            device_signature: cokret_sdk::Signature2 {
                kid: format!("{}#device", record.principal_id.as_str()),
                alg: Some("EdDSA".to_owned()),
                sig: "test-signature".to_owned(),
            },
            revocation_status: None,
            last_resort: None,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn invite_admission_builds_schema_valid_welcome_and_recipient_can_apply_it() {
        let mut alice_state = isolated_store_for_tests("invite-admission-alice");
        let mut bob_state = isolated_store_for_tests("invite-admission-bob");
        let secure = MemorySecureKeyStore::new();
        let realm = "ck:realm:01904100-0000-7000-8000-0000000000d1";
        let alice = "did:web:alice.example";
        let alice_device = "ck:device:01904100-0000-7000-8000-0000000000a1";
        let bob = "did:web:bob.example";
        let bob_device = "ck:device:01904100-0000-7000-8000-0000000000b1";

        let publish = install_cross_signing(&mut alice_state, &secure, alice, alice_device);
        ensure_creator_mls_snapshot(&mut alice_state, &secure, realm, alice, alice_device)
            .unwrap()
            .expect("creator snapshot");

        let bob_identity = cokret_sdk::CokretMlsIdentity::new_basic(
            cokret_sdk::Did::new(bob.to_owned()).unwrap(),
            cokret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
        )
        .unwrap();
        let bob_key_package = bob_identity.key_package_record().unwrap();
        let bob_private_state = bob_identity.export_private_state().unwrap();
        store_mls_key_package_identity_state(
            &secure,
            bob,
            bob_device,
            bob_key_package.keypackage_ref.as_str(),
            &bob_private_state,
        )
        .unwrap();
        let claim = claim_from_key_package(&bob_key_package, publish.generation);

        let admission = build_realm_mls_admission_events_from_claim(
            &alice_state,
            &secure,
            realm,
            alice,
            alice_device,
            &claim,
            "test-claim-nonce",
        )
        .unwrap();

        assert_eq!(admission.commit.kind.as_str(), "ck.mls.commit");
        assert_eq!(admission.welcome.kind.as_str(), "ck.mls.welcome");
        assert_eq!(
            admission.welcome.content["ciphertext"],
            admission.welcome_envelope.welcome
        );
        assert!(admission.welcome.content.get("welcome_bytes_b64").is_none());
        assert!(admission.welcome.content.get("key_package_id").is_none());
        assert!(
            admission.welcome.content["claim_envelope"]["signature"]["sig"]
                .as_str()
                .is_some_and(|sig| !sig.is_empty())
        );
        let catalog = cokret_sdk::schema::event_payload_validator_catalog();
        catalog
            .validate_payload(admission.welcome.kind.as_str(), &admission.welcome.content)
            .unwrap_or_else(|err| {
                panic!(
                    "ck.mls.welcome payload violates registered schema: {err}\npayload: {}",
                    serde_json::to_string_pretty(&admission.welcome.content).unwrap()
                )
            });

        let messages = json!({
            "messages": [{
                "kind": "ck.mls.welcome",
                "content": serde_json::to_value(&admission.welcome_envelope).unwrap(),
                "unsigned": {
                    "key_package_id": claim.keypackage_ref,
                },
            }],
        });
        let outcome = apply_welcome_messages_with_device_snapshot(
            &mut bob_state,
            &secure,
            realm,
            bob,
            bob_device,
            &messages,
        )
        .unwrap();

        assert_eq!(outcome.applied, 1, "{outcome:?}");
        assert_eq!(outcome.failed, 0, "{outcome:?}");
        assert!(bob_state.mls_snapshot_for(realm).is_some());
    }
}
