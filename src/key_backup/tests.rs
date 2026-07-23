use arkret_models_crypto::{KeyBackupContentItem, ManagedFrontierRef, ManagedPrincipalBinding};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::*;
use crate::recovery_crypto::{VAULT_SALT_LEN, VaultKek, derive_vault_kek_with_salt};

const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-00000000beef";
const ACTOR: &str = "did:web:alice.example";
const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
const DEVICE_AUTHORIZE_EVENT: &str = "ak:event:01964137-0000-7000-8000-000000000123";

fn test_root() -> VaultKek {
    derive_vault_kek_with_salt(b"correct horse battery staple", &[7u8; VAULT_SALT_LEN]).unwrap()
}

/// Test-only `secret_storage`/`recovery_vault` passphrase_kdf envelope —
/// the former UI-facing recovery-vault builder. Kept here as a fixture so
/// the shared seal / open / sign machinery in
/// [`build_passphrase_kdf_backup_body`] / [`open_passphrase_kdf_backup_body`]
/// stays covered.
fn build_recovery_vault_backup_body(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    root: &VaultKek,
    plaintext: &[u8],
) -> anyhow::Result<Value> {
    build_passphrase_kdf_backup_body(
        backup_id,
        actor_id,
        device_id,
        root,
        plaintext,
        BackupClass::SecretStorage,
        "recovery_vault",
        &KeyBackupContentItem {
            item_type: "recovery_secret".to_owned(),
            secret_id: Some("inkson_recovery_vault_payload".to_owned()),
            ..Default::default()
        },
    )
}

#[test]
fn managed_agent_pcr_binding_is_bound_into_hpke_aad() {
    let controller = arkret_sdk::Did::new(ACTOR).unwrap();
    let binding = ManagedPrincipalBinding {
        managed_principal_id: arkret_sdk::Did::new("did:web:agent.example").unwrap(),
        controller_id: controller,
        principal_control_realm_id: arkret_sdk::RealmId::new(
            "ak:realm:01964137-0000-7000-8000-000000000099",
        )
        .unwrap(),
        authorization_ref: "did:web:agent.example#managed-controller".to_owned(),
        managed_frontier_ref: ManagedFrontierRef {
            frontier_digest: arkret_sdk::Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            seal_ref: "ak:seal:01964137-0000-7000-8000-000000000098".to_owned(),
            mls_epoch: 0,
        },
    };
    let (_, recovery_public_key) = crate::hpke_backup::derive_recovery_keypair_from_entropy(
        &[9_u8; crate::recovery_crypto::RECOVERY_KEY_BYTES],
    )
    .unwrap();
    let body = build_recovery_public_key_backup_body(
        BACKUP_ID,
        ACTOR,
        DEVICE,
        &recovery_public_key,
        "did:web:alice.example#recovery",
        BackupClass::MlsHistory,
        "managed_agent_pcr",
        &KeyBackupContentItem {
            item_type: "mls_group_state".to_owned(),
            realm_id: Some(binding.principal_control_realm_id.clone()),
            managed_principal_binding: Some(binding.clone()),
            mls_group_id: Some("YWdlbnQtcGNy".to_owned()),
            epoch: Some(0),
            ..Default::default()
        },
        b"encrypted local MLS snapshot",
        Some(("ak:policy:01964137-0000-7000-8000-000000000077", 1)),
    )
    .unwrap();

    assert_eq!(
        body["domain_separation"]["aead_aad"]["managed_principal_bindings"],
        json!([binding])
    );
}

#[test]
fn build_recovery_vault_backup_body_seals_per_spec() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"vault payload")
        .unwrap();
    assert_eq!(body["backup_class"], "secret_storage");
    assert!(
        body["series_id"]
            .as_str()
            .is_some_and(is_protocol_backup_series_id)
    );
    assert_eq!(body["series_seq"], 0);
    assert!(body.get("supersedes").is_none());
    assert!(body.get("supersedes_digest").is_none());
    assert_eq!(body["encryption"]["recipient_method"], "passphrase_kdf");
    assert_eq!(body["encryption"]["kdf"]["name"], "argon2id");
    // Argon2id params come from the root KEK; salt/nonce/nonce_salt are real.
    assert_eq!(
        body["encryption"]["kdf"]["params"]["memory_kib"],
        root.m_kib
    );
    assert!(is_base64url_token(
        body["encryption"]["kdf"]["salt"].as_str().unwrap()
    ));
    assert_eq!(body["encryption"]["aead"]["name"], "xchacha20_poly1305");
    assert_eq!(
        body["encryption"]["aead"]["aead_profile"],
        "ak.aead.xchacha20_poly1305.v1"
    );
    assert!(is_base64url_token(
        body["encryption"]["aead"]["nonce"].as_str().unwrap()
    ));
    // Spec §7.5 additions: nonce_salt + key_commitment present.
    assert!(is_base64url_token(
        body["encryption"]["aead"]["nonce_salt"].as_str().unwrap()
    ));
    assert!(is_sha_digest(
        body["encryption"]["key_commitment"].as_str().unwrap()
    ));
    assert_eq!(body["contents"][0]["item_type"], "recovery_secret");
    assert!(is_base64url_token(body["ciphertext"].as_str().unwrap()));
    assert_eq!(body["device_id"], DEVICE);
    assert_eq!(
        body["domain_separation"]["hkdf_info"],
        "arkret-key-backup/secret_storage/recovery_vault/v1"
    );
    validate_key_backup_put_request(BACKUP_ID, &body)
        .expect("secret_storage recovery vault envelope should validate");
}

#[test]
fn key_backup_auth_data_sign_verify_round_trip() {
    let root = test_root();
    let mut body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let vm = format!("{ACTOR}#cx_device_01964137");
    sign_key_backup_auth_data(
        &mut body,
        &signing_key,
        DEVICE,
        &vm,
        Some(KeyBackupDeviceTrustAnchor::SskGeneration(7)),
    )
    .unwrap();

    assert_eq!(body["auth_data"]["verification_method"], vm);
    assert_eq!(body["auth_data"]["signature_algorithm"], "Ed25519");
    assert_eq!(body["auth_data"]["ssk_generation"], 7);
    // signed_fields must cover the mandatory set (+ series fields present).
    let signed: Vec<String> = body["auth_data"]["signed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    for f in KEY_BACKUP_SIGNED_FIELDS_MANDATORY {
        assert!(signed.contains(&f.to_string()), "missing signed field {f}");
    }
    assert!(
        !signed.contains(&"supersedes".to_string()),
        "genesis envelopes must not sign absent supersedes"
    );

    verify_key_backup_auth_data(&body, &signing_key.verifying_key())
        .expect("freshly signed backup must verify");
}

#[test]
fn key_backup_auth_data_sign_verify_service_attested_round_trip() {
    let root = test_root();
    let mut body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    let signing_key = SigningKey::from_bytes(&[44u8; 32]);
    sign_key_backup_auth_data(
        &mut body,
        &signing_key,
        DEVICE,
        "did:web:a#device",
        Some(KeyBackupDeviceTrustAnchor::DeviceAuthorizeEventId(
            DEVICE_AUTHORIZE_EVENT.to_owned(),
        )),
    )
    .unwrap();

    assert_eq!(
        body["auth_data"]["device_authorize_event_id"],
        DEVICE_AUTHORIZE_EVENT
    );
    assert!(body["auth_data"].get("ssk_generation").is_none());
    let parsed: arkret_sdk::KeyBackup = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(
        parsed
            .auth_data
            .unwrap()
            .device_authorize_event_id
            .unwrap()
            .as_str(),
        DEVICE_AUTHORIZE_EVENT
    );
    verify_key_backup_auth_data(&body, &signing_key.verifying_key())
        .expect("service-attested backup signature must verify");
}

#[test]
fn recovery_policy_ref_is_covered_by_signed_fields_when_present() {
    // 6.2 — when recovery_policy_ref is on the envelope, the signer MUST
    // cover it (so the policy binding can't be stripped/tampered).
    let root = test_root();
    let mut body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    body["recovery_policy_ref"] = json!({
        "policy_id": "ak:policy:01964137-0000-7000-8000-0000000000aa",
        "policy_version": 3,
    });
    let signing_key = SigningKey::from_bytes(&[43u8; 32]);
    sign_key_backup_auth_data(
        &mut body,
        &signing_key,
        DEVICE,
        "did:web:a#device",
        Some(KeyBackupDeviceTrustAnchor::SskGeneration(7)),
    )
    .unwrap();
    let signed: Vec<String> = body["auth_data"]["signed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert!(
        signed.contains(&"recovery_policy_ref".to_string()),
        "recovery_policy_ref must be signed: {signed:?}"
    );
    verify_key_backup_auth_data(&body, &signing_key.verifying_key())
        .expect("signed backup with recovery_policy_ref must verify");
}

#[test]
fn sign_key_backup_with_active_device_is_noop_helper_signs_directly() {
    // The build-path integration uses the process-wide signer slot, which
    // races with other tests; the signing CORRECTNESS is covered by the
    // round-trip/tamper tests. Here we just confirm the direct signing
    // helper produces a self-verifying envelope (deterministic, no globals).
    let root = test_root();
    let mut body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    let signing_key = SigningKey::from_bytes(&[55u8; 32]);
    sign_key_backup_auth_data(
        &mut body,
        &signing_key,
        DEVICE,
        "did:web:alice.example#device",
        Some(KeyBackupDeviceTrustAnchor::SskGeneration(1)),
    )
    .unwrap();
    verify_key_backup_auth_data(&body, &signing_key.verifying_key())
        .expect("built+signed backup must self-verify");
}

#[test]
fn key_backup_auth_data_rejects_tamper_and_wrong_key() {
    let root = test_root();
    let mut body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    sign_key_backup_auth_data(
        &mut body,
        &signing_key,
        DEVICE,
        "did:web:a#device",
        Some(KeyBackupDeviceTrustAnchor::SskGeneration(1)),
    )
    .unwrap();

    // Tamper a signed field (ciphertext is covered via ciphertext_digest, but
    // mutate backup_class which is in signed_fields) → verify fails.
    let mut tampered = body.clone();
    tampered["backup_class"] = json!("did_recovery");
    assert!(verify_key_backup_auth_data(&tampered, &signing_key.verifying_key()).is_err());

    // Wrong verifying key → fails.
    let other = SigningKey::from_bytes(&[10u8; 32]);
    let err = verify_key_backup_auth_data(&body, &other.verifying_key()).unwrap_err();
    assert!(err.contains("untrusted_backup_signature"));
}

#[test]
fn recovery_vault_round_trips_through_open() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"secret payload")
        .unwrap();
    let recovered =
        open_passphrase_kdf_backup_body(b"correct horse battery staple", &body).unwrap();
    assert_eq!(recovered, b"secret payload");
    // Wrong passphrase fails fast via key_commitment.
    let err = open_passphrase_kdf_backup_body(b"wrong", &body).unwrap_err();
    assert!(err.to_string().contains("key_commitment mismatch"));
}

#[test]
fn open_refuses_tampered_ciphertext_via_digest_mismatch() {
    // key-management.md §7.2: `ciphertext_digest` covers the ciphertext bytes.
    // A client opening a downloaded backup MUST refuse to decrypt when the
    // recomputed digest does not match the envelope's `ciphertext_digest`,
    // catching a substituted / tampered ciphertext locally (no server GET).
    let root = test_root();
    let mut body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"secret payload")
            .unwrap();
    // Sanity: the untampered body opens with the correct passphrase.
    assert_eq!(
        open_passphrase_kdf_backup_body(b"correct horse battery staple", &body).unwrap(),
        b"secret payload"
    );

    // Re-seal a DIFFERENT plaintext under a fresh context to get a valid but
    // unrelated ciphertext, then splice it in WITHOUT updating the envelope's
    // `ciphertext_digest`. This models an attacker substituting the ciphertext
    // while leaving the signed/declared digest intact.
    let other =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"attacker payload")
            .unwrap();
    body["ciphertext"] = other["ciphertext"].clone();
    let err = open_passphrase_kdf_backup_body(b"correct horse battery staple", &body)
        .expect_err("digest mismatch must refuse decryption");
    assert!(
        err.to_string().contains("ciphertext_digest mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn did_recovery_backup_uses_separate_domain_and_hpke() {
    let (sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    let body = build_did_recovery_backup_body(
        "ak:backup:01964137-0000-7000-8000-00000000d1d0",
        ACTOR,
        DEVICE,
        &pk,
        "did:web:alice.example#recovery",
        b"recovery share",
        "ak:policy:01964137-0000-7000-8000-0000000000aa",
        1,
    )
    .unwrap();

    assert_eq!(body["backup_class"], "did_recovery");
    assert_eq!(
        body["encryption"]["recipient_method"],
        "recovery_public_key"
    );
    // 6.2 — did_recovery MUST carry recovery_policy_ref (top-level).
    assert_eq!(
        body["recovery_policy_ref"]["policy_id"],
        "ak:policy:01964137-0000-7000-8000-0000000000aa"
    );
    assert_eq!(body["recovery_policy_ref"]["policy_version"], 1);
    assert!(
        body["series_id"]
            .as_str()
            .is_some_and(is_protocol_backup_series_id)
    );
    assert_eq!(body["series_seq"], 0);
    assert_eq!(body["contents"][0]["item_type"], "recovery_key_share");
    assert_eq!(
        body["domain_separation"]["hkdf_info"],
        "arkret-key-backup/did_recovery/recovery_policy/v1"
    );
    validate_key_backup_envelope(&body, Some(BackupClass::DidRecovery))
        .expect("did_recovery HPKE envelope should validate");
    // Round-trips with the recovery private key.
    assert_eq!(
        open_recovery_public_key_backup_body(&sk, &body).unwrap(),
        b"recovery share"
    );
}

#[test]
fn did_recovery_passphrase_kdf_is_rejected() {
    // Spec §5.0.1 first-backup gate: passphrase_kdf-only did_recovery forbidden.
    let root = test_root();
    let mut body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    body["backup_class"] = json!("did_recovery");
    body["contents"][0]["item_type"] = json!("recovery_key_share");
    attach_key_backup_domain_separation(&mut body, BackupClass::DidRecovery, "recovery_policy");
    let err = validate_key_backup_envelope(&body, Some(BackupClass::DidRecovery))
        .expect_err("passphrase_kdf did_recovery must be rejected");
    assert!(err.contains("did_recovery"), "{err}");
}

#[test]
fn key_backup_validator_rejects_cross_domain_item_mix() {
    let root = test_root();
    let mut body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    body["contents"][0]["item_type"] = json!("mls_group_state");
    attach_key_backup_domain_separation(&mut body, BackupClass::SecretStorage, "recovery_vault");

    let err = validate_key_backup_envelope(&body, Some(BackupClass::SecretStorage))
        .expect_err("secret_storage must not carry MLS history items");
    assert!(err.contains("not allowed"));
}

#[test]
fn key_backup_validator_rejects_recipient_method_aad_mismatch() {
    // SEC-04: the AAD's recipient_method binding must agree with the envelope's
    // encryption.recipient_method. Swapping the method after sealing (without
    // recomputing the AAD) MUST be rejected.
    let root = test_root();
    let mut body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    // Sanity: as-built (passphrase_kdf) it validates and its AAD pins the method.
    validate_key_backup_envelope(&body, Some(BackupClass::SecretStorage))
        .expect("freshly built recovery vault backup validates");
    assert_eq!(
        body["domain_separation"]["aead_aad"]["recipient_method"],
        json!("passphrase_kdf"),
        "AAD must bind the recipient_method"
    );
    // Tamper the AAD's recipient_method so it disagrees with
    // encryption.recipient_method → the SEC-04 cross-check must reject it.
    body["domain_separation"]["aead_aad"]["recipient_method"] = json!("recovery_public_key");
    let err = validate_key_backup_envelope(&body, Some(BackupClass::SecretStorage))
        .expect_err("recipient_method/AAD mismatch must be rejected");
    assert!(err.contains("recipient_method"), "{err}");
}

#[test]
fn key_backup_validator_rejects_missing_domain_separation() {
    let root = test_root();
    let mut body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    body.as_object_mut().unwrap().remove("domain_separation");

    let err = validate_key_backup_envelope(&body, Some(BackupClass::SecretStorage))
        .expect_err("domain separation metadata is required");
    assert!(err.contains("domain_separation"));
}

#[test]
fn key_backup_validator_rejects_missing_series_fields() {
    let root = test_root();
    let mut body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    body.as_object_mut().unwrap().remove("series_id");

    let err = validate_key_backup_envelope(&body, Some(BackupClass::SecretStorage))
        .expect_err("series_id is mandatory");
    assert!(err.contains("series_id"));
}

#[test]
fn mls_history_rejects_passphrase_kdf() {
    let root = test_root();
    let mut body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    body["backup_class"] = json!("mls_history");
    body["contents"][0]["item_type"] = json!("mls_group_state");
    attach_key_backup_domain_separation(&mut body, BackupClass::MlsHistory, "mls_snapshot");

    let err = validate_key_backup_envelope(&body, Some(BackupClass::MlsHistory))
        .expect_err("MLS history passphrase KDF backup must be rejected");
    assert!(err.contains("secret_storage_key"));
}

#[test]
fn mls_history_accepts_secret_storage_key() {
    let envelope = crate::mls::persistence::encrypt_state(
        "ak:realm:demo",
        "group-a",
        3,
        b"opaque sdk state",
        "device-secret",
        b"salt",
    );
    let body = envelope.to_key_backup_body(
        "ak:backup:01964137-0000-7000-8000-00000000feed",
        ACTOR,
        DEVICE,
    );
    assert_eq!(body["encryption"]["recipient_method"], "secret_storage_key");
    assert_eq!(
        body["encryption"]["recipient_key_ref"],
        "mls_group_secrets_backup_key"
    );
    validate_key_backup_envelope(&body, Some(BackupClass::MlsHistory))
        .expect("mls_history secret_storage_key envelope should validate");
}

#[test]
fn recovery_public_key_backup_round_trips_and_validates() {
    let (sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    let body = build_recovery_public_key_backup_body(
        BACKUP_ID,
        ACTOR,
        DEVICE,
        &pk,
        "did:web:alice.example#recovery",
        BackupClass::MlsHistory,
        "mls_snapshot",
        &KeyBackupContentItem {
            item_type: "mls_group_state".to_owned(),
            secret_id: Some("inkson_mls_snapshot".to_owned()),
            ..Default::default()
        },
        b"opaque mls snapshot bytes",
        None,
    )
    .unwrap();

    assert_eq!(
        body["encryption"]["recipient_method"],
        "recovery_public_key"
    );
    assert_eq!(
        body["encryption"]["recipient_key_ref"],
        "did:web:alice.example#recovery"
    );
    assert!(is_base64url_token(
        body["encryption"]["aead"]["enc"].as_str().unwrap()
    ));
    assert!(body["encryption"]["aead"].get("nonce").is_none());
    validate_key_backup_envelope(&body, Some(BackupClass::MlsHistory))
        .expect("recovery_public_key mls_history envelope should validate");

    // The recovery private key opens it (the fresh-device restore path);
    // a different recovery key cannot.
    let opened = open_recovery_public_key_backup_body(&sk, &body).unwrap();
    assert_eq!(opened, b"opaque mls snapshot bytes");
    let (other_sk, _other_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    assert!(open_recovery_public_key_backup_body(&other_sk, &body).is_err());
}

#[test]
fn mls_history_rejects_obvious_plaintext_fields() {
    let envelope = crate::mls::persistence::encrypt_state(
        "ak:realm:demo",
        "group-a",
        3,
        b"not real sdk state",
        "device-secret",
        b"salt",
    );
    let mut body = envelope.to_key_backup_body(
        "ak:backup:01964137-0000-7000-8000-00000000beef",
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    body["serialized_state"] = json!("plaintext sdk bytes");

    let err = validate_key_backup_envelope(&body, Some(BackupClass::MlsHistory))
        .expect_err("MLS history backups must stay opaque");
    assert!(err.contains("plaintext field"));
}

#[test]
fn key_backup_validator_rejects_weak_argon2id() {
    let root = test_root();
    let mut body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    // Force the wire params below the profile floor (the builder always uses
    // the strong root params, so weaken them post-build to exercise the
    // validator).
    body["encryption"]["kdf"]["params"]["memory_kib"] = json!(1);
    body["encryption"]["kdf"]["params"]["iterations"] = json!(1);

    let err = validate_key_backup_envelope(&body, Some(BackupClass::SecretStorage))
        .expect_err("weak KDF parameters must be rejected");
    assert!(err.contains("argon2id"));
}

#[test]
fn key_backup_put_request_rejects_path_body_mismatch() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();

    let err =
        validate_key_backup_put_request("ak:backup:01964137-0000-7000-8000-00000000badd", &body)
            .expect_err("path/body backup id mismatch must be rejected");
    assert!(err.contains("mismatch"));
}

#[test]
fn delete_ownership_proof_binds_actor_and_backup() {
    assert_eq!(
        key_backup_delete_ownership_proof(
            "did:web:alice.example",
            "ak:backup:01964137-0000-7000-8000-00000000beef"
        ),
        "dev-ssk-delete:v1:did:web:alice.example:ak:backup:01964137-0000-7000-8000-00000000beef"
    );
}
