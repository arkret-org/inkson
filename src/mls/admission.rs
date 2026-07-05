use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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

pub(crate) struct RealmMlsBatchAdmissionEvents {
    pub(crate) commit: cokret_sdk::Event,
    pub(crate) welcomes: Vec<cokret_sdk::Event>,
    pub(crate) snapshot: MlsSnapshotEnvelope,
}

pub(crate) fn build_realm_mls_admission_events_from_claim(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    claim: &cokret_sdk::KeyPackageClaimRecord,
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
    let commit = crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
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
        &add.welcome,
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

pub(crate) fn build_realm_mls_admission_events_from_claims(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    claims: &[(cokret_sdk::KeyPackageClaimRecord, String)],
) -> Result<RealmMlsBatchAdmissionEvents, String> {
    if claims.is_empty() {
        return Err("MLS admission batch requires at least one claim".to_owned());
    }
    let member_key_packages = claims
        .iter()
        .map(|(claim, _)| {
            crate::api::keypackage_claim_record_to_mls_record(claim)
                .map_err(|err| format!("MLS KeyPackage claim decode failed: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (add, snapshot) = crate::mls::runtime::build_add_members_commit_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        actor_id,
        device_id,
        &member_key_packages,
    )
    .map_err(|err| err.user_message())?;
    let commit = crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
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
    if add.welcomes.len() != claims.len() {
        return Err("MLS batch add returned a mismatched Welcome count".to_owned());
    }
    let mut welcomes = Vec::with_capacity(claims.len());
    for ((claim, claim_nonce), (member_key_package, welcome_envelope)) in claims
        .iter()
        .zip(member_key_packages.iter().zip(add.welcomes.iter()))
    {
        let welcome_payload = build_mls_welcome_payload_value(
            state_store,
            secure_store,
            realm_id,
            actor_id,
            device_id,
            claim,
            &member_key_package.keypackage_id,
            welcome_envelope,
            &commit,
            governance_binding.clone(),
            claim_nonce,
        )?;
        let welcome = crate::operation::ck_ops::mls_welcome_with_governance(
            realm_id,
            actor_id,
            &welcome_envelope.group_id,
            &welcome_payload,
        )
        .build_sdk_event("yougen")
        .map_err(|err| format!("MLS Welcome SDK Event conversion failed: {err}"))?;
        welcomes.push(welcome);
    }
    Ok(RealmMlsBatchAdmissionEvents {
        commit,
        welcomes,
        snapshot,
    })
}

/// Build a `ck.realm_key.share` event carrying a HPKE-sealed bundle of
/// retained `history_secret`s so `recipient` can decrypt pre-join
/// `mls-exporter-aead-v1` content (`encryption-and-audit.md` history sharing).
///
/// `sealed_ciphertext` is the `base64url(eph_pub || ct)` blob produced by
/// [`crate::mls::secret_share::seal_history_secret_to_device_pubkey`] for the
/// recipient device's advertised HPKE public key. `from_epoch`/`to_epoch` bound
/// the shared range and are recorded in the `key_scope` so the receiver can
/// match the share to the epochs it is missing.
///
/// The provider MUST have built `sealed_ciphertext` against the recipient's
/// HPKE public key; this builder does not derive or validate that key.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_realm_key_share_event(
    realm_id: &str,
    actor_id: &str,
    sender_device_id: &str,
    recipient_principal_id: &str,
    recipient_device_id: &str,
    from_epoch: u64,
    to_epoch: u64,
    policy_digest: String,
    sealed_ciphertext: String,
) -> Result<cokret_sdk::Event, String> {
    let recipient_did = cokret_sdk::Did::new(recipient_principal_id.trim().to_owned())
        .map_err(|err| format!("invalid realm_key.share recipient DID: {err:?}"))?;
    let policy_digest = cokret_sdk::Hash::new(policy_digest.trim().to_owned())
        .map_err(|err| format!("invalid realm_key.share policy_digest: {err:?}"))?;
    let key_scope = cokret_sdk::RealmKeyScope {
        effective_scope: crate::operation::realm_effective_scope_value(realm_id)?,
        policy_digest: Value::String(policy_digest.as_str().to_owned()),
        membership_frontier_digest: None,
        from_epoch: Some(from_epoch),
        to_epoch: Some(to_epoch),
        history_visibility: None,
    };
    let mut payload = cokret_sdk::RealmKeySharePayload {
        share_class: cokret_sdk::RealmKeyShareClass::MemberDevice,
        recipient_principal_id: recipient_did,
        recipient_device_id: Some(recipient_device_id.trim().to_owned()),
        recipient_verification_method: None,
        recovery_recipient_id: None,
        sender_device_id: sender_device_id.trim().to_owned(),
        // Filled below with a real Ed25519 signature over
        // `RealmKeySharePayload::sender_signing_input()` (device-lifecycle.md
        // §13). Initialized empty only while constructing the signing input and
        // replaced before the Event is serialized. The per-secret HPKE seal
        // (AEAD tag) bound to the recipient device already covers confidentiality
        // + integrity of the shared keys; this detached signature additionally
        // authenticates the *sender device* to the receiver, independent of the
        // durable Event-envelope proof.
        sender_device_signature: json!({}),
        key_scope,
        ciphertext: Some(sealed_ciphertext),
        encrypted_key_ref: None,
        aad_digest: None,
        expires_at: None,
        created_at: crate::clock::now_utc_secs(),
    };
    // Sign `sender_signing_input()` with this device's active Ed25519 event
    // signer and embed the detached signature. The registered payload schema
    // requires this signature, so a provider without an active signer must
    // fail closed and retry after device signing is ready.
    payload.sender_device_signature = sign_realm_key_share_sender_signature(&payload)
        .ok_or_else(|| "ck.realm_key.share requires an active sender device signer".to_owned())?;
    let body = serde_json::to_value(&payload)
        .map_err(|err| format!("serialize ck.realm_key.share payload: {err}"))?;
    crate::operation::OperationBuilder::new(
        realm_id,
        actor_id,
        cokret_sdk::events::kinds::EventKind::RealmKeyShare,
    )
    .body(body)
    .build_sdk_event("yougen")
    .map_err(|err| format!("ck.realm_key.share SDK Event conversion failed: {err}"))
}

/// Wrap an already-constructed [`cokret_sdk::RealmKeySharePayload`] (e.g. the
/// provider-initiated RRK seal produced by
/// `cokret_sdk::history_recovery::seal_history_secrets_to_recovery_recipient`)
/// into a durable `ck.realm_key.share` Event, filling the
/// `sender_device_signature` with this device's active Ed25519 signer. The
/// registered payload schema requires this signature, so this fails closed when
/// no active signer is installed.
///
/// Unlike [`build_realm_key_share_event`], the seal + payload are already done by
/// the SDK authority; this only authenticates the sender device and converts to
/// a wire Event.
pub(crate) fn wrap_realm_key_share_payload_event(
    realm_id: &str,
    actor_id: &str,
    mut payload: cokret_sdk::RealmKeySharePayload,
) -> Result<cokret_sdk::Event, String> {
    payload.sender_device_signature = sign_realm_key_share_sender_signature(&payload)
        .ok_or_else(|| "ck.realm_key.share requires an active sender device signer".to_owned())?;
    let body = serde_json::to_value(&payload)
        .map_err(|err| format!("serialize ck.realm_key.share payload: {err}"))?;
    crate::operation::OperationBuilder::new(
        realm_id,
        actor_id,
        cokret_sdk::events::kinds::EventKind::RealmKeyShare,
    )
    .body(body)
    .build_sdk_event("yougen")
    .map_err(|err| format!("ck.realm_key.share SDK Event conversion failed: {err}"))
}

/// Sign the canonical `RealmKeySharePayload::sender_signing_input()` with this
/// device's active Ed25519 event signer (raw signature over canonical JSON,
/// not a detached JWS — the receiver verifies the raw signature in
/// [`crate::mls::runtime::verify_realm_key_share_sender_signature`]).
///
/// Returns a typed `sender_device_signature` object:
/// ```json
/// { "alg": "Ed25519", "signature": "<b64url>", "signer_public_key_multibase": "z.." }
/// ```
/// or `None` when no raw-capable signer is installed.
pub(crate) fn sign_realm_key_share_sender_signature(
    payload: &cokret_sdk::RealmKeySharePayload,
) -> Option<Value> {
    let signer = crate::event_signer::active_signer()?;
    let pubkey_multibase = signer.public_key_multibase()?;
    let signing_input = payload.sender_signing_input();
    let signature = signer.sign_raw(&signing_input).ok()?;
    Some(json!({
        "alg": "Ed25519",
        "signature": URL_SAFE_NO_PAD.encode(signature),
        "signer_public_key_multibase": pubkey_multibase,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_mls_welcome_payload_value(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    sender_device_id: &str,
    claim: &cokret_sdk::KeyPackageClaimRecord,
    _key_package_id: &str,
    welcome: &cokret_sdk::MlsWelcomeEnvelope,
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
        ssk_generation: None,
        requester_device_id: None,
        nonce: claim_nonce.trim().to_owned(),
        welcome_digest: welcome.welcome_hash.clone(),
        created_at: crate::clock::now_utc(),
        signature: cokret_sdk::KeyOperationSignature {
            kid: String::new(),
            alg: Some("EdDSA".to_owned()),
            sig: String::new(),
        },
    };
    sign_welcome_claim_envelope(
        state_store,
        secure_store,
        actor_id,
        sender_device_id,
        &mut envelope,
    )?;
    let claim_ref = cokret_sdk::MlsWelcomePayloadClaimRef {
        claim_id: claim.claim_id.clone(),
        keypackage_ref: claim.keypackage_ref.clone(),
        keypackage_digest: claim.keypackage_digest.clone(),
        capabilities_digest: claim.capabilities_digest.clone(),
        ssk_generation: claim.ssk_generation,
        device_authorize_event_id: claim.device_authorize_event_id.clone(),
    };
    let commit_ref = commit_event.event_id.as_str().to_owned();
    Ok(json!({
        "mls_group_id": welcome.group_id,
        "epoch": welcome.epoch,
        "recipient_principal_id": claim.principal_id,
        "recipient_device_id": claim.device_id,
        "sender_device_id": sender_device_id,
        "keypackage_ref": claim.keypackage_ref,
        "keypackage_digest": claim.keypackage_digest,
        "claim_id": claim.claim_id,
        "claim_ref": claim_ref,
        "claim_envelope": envelope,
        "ciphertext": welcome.welcome,
        "commit_ref": commit_ref,
        "governance_binding": governance_binding,
        "expires_at": claim.expires_at,
    }))
}

fn sign_welcome_claim_envelope(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    actor_id: &str,
    sender_device_id: &str,
    envelope: &mut cokret_sdk::MlsWelcomeClaimEnvelope,
) -> Result<(), String> {
    if let Some(publish) = load_latest_cross_signing_publish(state_store, actor_id)? {
        envelope.ssk_generation = Some(publish.generation);
        envelope.requester_device_id = None;
        envelope.signature.kid = publish.self_signing_key.key.kid.clone();
        let signing_bytes = envelope
            .canonical_signing_bytes()
            .map_err(|err| format!("MLS Welcome claim canonical bytes: {err}"))?;
        let signing_key = load_signing_key(
            secure_store,
            actor_id,
            publish.generation,
            CrossSigningKeyRole::SelfSigning,
        )
        .map_err(|err| format!("load self-signing key: {err}"))?
        .ok_or_else(|| "self-signing key is not available on this device".to_owned())?;
        let signature = signing_key.sign(&signing_bytes);
        envelope.signature.sig = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        return Ok(());
    }
    let sender_device_id = sender_device_id.trim();
    if sender_device_id.is_empty() {
        return Err("MLS Welcome device signature requires sender_device_id".to_owned());
    }
    envelope.ssk_generation = None;
    envelope.requester_device_id = Some(sender_device_id.to_owned());
    let signer = match crate::event_signer::active_signer() {
        Some(signer) => signer,
        None => crate::event_signer::bootstrap_default_signer("yougen")
            .map_err(|err| format!("MLS Welcome device signer bootstrap: {err}"))?,
    };
    envelope.signature.kid = signer.verification_method().to_owned();
    let signing_bytes = envelope
        .canonical_signing_bytes()
        .map_err(|err| format!("MLS Welcome claim canonical bytes: {err}"))?;
    let signature = signer
        .sign_raw(&signing_bytes)
        .map_err(|err| format!("MLS Welcome device signature: {err}"))?;
    envelope.signature.sig = URL_SAFE_NO_PAD.encode(signature);
    Ok(())
}

fn load_latest_cross_signing_publish(
    state_store: &LocalStateStore,
    actor_id: &str,
) -> Result<Option<cokret_sdk::CrossSigningPublishContent>, String> {
    let Some(raw) = state_store.load_private_data(actor_id, CROSS_SIGNING_PUBLISH_LATEST_KEY)
    else {
        return Ok(None);
    };
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|err| format!("cross-signing publish state decode: {err}"))
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

    struct ActiveSignerGuard(Option<std::sync::Arc<crate::event_signer::YougenEventSigner>>);

    impl ActiveSignerGuard {
        fn install(seed: [u8; 32], signer_did: &str) -> Self {
            let signer =
                std::sync::Arc::new(crate::event_signer::build_ed25519_signer(seed, signer_did));
            Self(crate::event_signer::replace_active_signer(Some(signer)))
        }
    }

    impl Drop for ActiveSignerGuard {
        fn drop(&mut self) {
            let previous = self.0.take();
            let _ = crate::event_signer::replace_active_signer(previous);
        }
    }

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
    ) -> cokret_sdk::KeyPackageClaimRecord {
        cokret_sdk::KeyPackageClaimRecord {
            claim_id: "ck:mls_keypackage:test:Y2xhaW0tbm9uY2U".to_owned(),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            keypackage_digest: record.keypackage_ref.clone(),
            principal_id: record.principal_id.clone(),
            device_id: record.device_id.as_str().to_owned(),
            key_package: record.key_package.clone(),
            capabilities: record.capabilities.clone(),
            capabilities_digest: record.keypackage_ref.clone(),
            ssk_generation: Some(ssk_generation),
            device_authorize_event_id: None,
            expires_at: crate::clock::now_utc() + chrono::Duration::hours(1),
            device_signature: cokret_sdk::KeyOperationSignature {
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
    fn welcome_device_signature_uses_active_device_signer() {
        let state = isolated_store_for_tests("welcome-device-signer-secure-store");
        let secure = MemorySecureKeyStore::new();
        let active_signer = std::sync::Arc::new(crate::event_signer::build_ed25519_signer(
            [7u8; 32],
            "did:key:zActiveSigner",
        ));
        let expected_kid = active_signer.verification_method().to_owned();
        let previous = crate::event_signer::replace_active_signer(Some(active_signer));
        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-0000000000a1";
        let mut envelope = cokret_sdk::MlsWelcomeClaimEnvelope {
            keypackage_ref:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            keypackage_digest: cokret_sdk::Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            intended_realm_id: cokret_sdk::RealmId::new(
                "ck:realm:01904100-0000-7000-8000-0000000000d1",
            )
            .unwrap(),
            claim_id: "ck:mls:kp:test:nonce".to_owned(),
            requester_did: cokret_sdk::Did::new(actor.to_owned()).unwrap(),
            ssk_generation: None,
            requester_device_id: None,
            nonce: "nonce".to_owned(),
            welcome_digest: cokret_sdk::Hash::new(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            created_at: crate::clock::now_utc(),
            signature: cokret_sdk::KeyOperationSignature {
                kid: String::new(),
                alg: Some("EdDSA".to_owned()),
                sig: String::new(),
            },
        };

        sign_welcome_claim_envelope(&state, &secure, actor, device, &mut envelope).unwrap();

        assert_eq!(envelope.requester_device_id.as_deref(), Some(device));
        assert_eq!(envelope.signature.kid, expected_kid);
        assert!(!envelope.signature.sig.is_empty());
        assert!(!envelope.signature.sig.contains(['+', '/', '=']));
        assert!(
            URL_SAFE_NO_PAD
                .decode(envelope.signature.sig.as_bytes())
                .is_ok()
        );
        let _ = crate::event_signer::replace_active_signer(previous);
    }

    #[test]
    fn realm_key_share_event_matches_registered_payload_schema() {
        let _signer_guard =
            ActiveSignerGuard::install([9u8; 32], "did:key:zRealmKeyShareSchemaTest");
        let realm = "ck:realm:01904100-0000-7000-8000-0000000000d7";
        let policy_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        let event = build_realm_key_share_event(
            realm,
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-0000000000a1",
            "did:web:bob.example",
            "ck:device:01904100-0000-7000-8000-0000000000b1",
            0,
            2,
            policy_digest.clone(),
            "c2VhbGVk".to_owned(),
        )
        .unwrap();

        let catalog = cokret_sdk::schema::event_payload_validator_catalog().unwrap();
        catalog
            .validate_payload(event.kind.as_str(), &event.content)
            .unwrap_or_else(|err| {
                panic!(
                    "ck.realm_key.share payload violates registered schema: {err}\npayload: {}",
                    serde_json::to_string_pretty(&event.content).unwrap()
                )
            });
        assert_eq!(
            event.content["key_scope"]["effective_scope"],
            json!({ "kind": "realm", "realm_id": realm })
        );
        assert_eq!(event.content["key_scope"]["policy_digest"], policy_digest);
        let created_at = event.content["created_at"]
            .as_str()
            .expect("realm_key.share created_at is a string");
        cokret_sdk::canonical::validate_timestamp_canonical(created_at)
            .expect("realm_key.share created_at is canonical RFC3339 UTC");
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
        let genesis_summary =
            ensure_creator_mls_snapshot(&mut alice_state, &secure, realm, alice, alice_device)
                .unwrap()
                .expect("creator snapshot");
        let genesis_event = crate::mls::group_events::build_creator_mls_genesis_event(
            &mut alice_state,
            realm,
            alice,
            alice_device,
            Some(&genesis_summary),
        )
        .unwrap()
        .expect("creator genesis event");
        alice_state.mark_mls_genesis_emitted_with_event(realm, &genesis_event.event_id);

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
        assert_eq!(
            admission.commit.content["base_epoch_ref"],
            json!(genesis_event.event_id.as_str())
        );
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
        let catalog = cokret_sdk::schema::event_payload_validator_catalog().unwrap();
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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn admission_commit_reuses_genesis_policy_root_after_state_root_advances() {
        // Regression for the encrypted-Realm fork: an admin who does any
        // non-policy work (create a space/strand, send a message) between
        // creating the Realm and inviting advances the Seal `state_root`. The
        // add-member `ck.mls.commit` MUST still declare the genesis-locked
        // `policy_root`; otherwise soland rejects it `governance_binding_mismatch`
        // while its Welcome still lands, leaving the invitee at epoch N+1 and the
        // admin at epoch N — a permanent, mutually-undecryptable fork.
        let mut alice_state = isolated_store_for_tests("admission-policy-root-alice");
        let secure = MemorySecureKeyStore::new();
        let realm = "ck:realm:01904100-0000-7000-8000-0000000000e1";
        let alice = "did:web:alice.example";
        let alice_device = "ck:device:01904100-0000-7000-8000-0000000000a1";
        let bob = "did:web:bob.example";
        let bob_device = "ck:device:01904100-0000-7000-8000-0000000000b1";

        let publish = install_cross_signing(&mut alice_state, &secure, alice, alice_device);
        let genesis_summary =
            ensure_creator_mls_snapshot(&mut alice_state, &secure, realm, alice, alice_device)
                .unwrap()
                .expect("creator snapshot");
        let genesis_event = crate::mls::group_events::build_creator_mls_genesis_event(
            &mut alice_state,
            realm,
            alice,
            alice_device,
            Some(&genesis_summary),
        )
        .unwrap()
        .expect("creator genesis event");
        alice_state.mark_mls_genesis_emitted_with_event(realm, &genesis_event.event_id);
        let genesis_policy_root = genesis_event.content["governance_binding"]["policy_root"]
            .as_str()
            .expect("genesis governance binding carries policy_root")
            .to_owned();

        // Advance the Seal `state_root` the way ordinary post-genesis activity
        // (space/strand/message creates) would before the invite.
        let mut advanced = alice_state.seal_view_for_realm(realm);
        advanced.state_root = Some(
            "ck:state:sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
        );
        alice_state.set_realm_seal_view(realm, advanced);

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

        let commit_policy_root = admission.commit.content["governance_binding"]["policy_root"]
            .as_str()
            .expect("commit governance binding carries policy_root");
        assert_eq!(
            commit_policy_root, genesis_policy_root,
            "admission commit MUST reuse the genesis-locked policy_root even after the Seal state_root advanced"
        );
    }
}
