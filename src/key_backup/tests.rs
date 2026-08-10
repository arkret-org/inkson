use arkret_models_crypto::{
    KeyBackup, KeyBackupContentItem, ManagedFrontierRef, ManagedPrincipalBinding,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

use super::*;
use crate::recovery_crypto::{VAULT_SALT_LEN, VaultKek, derive_vault_kek_with_salt};

const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-00000000beef";
const ACTOR: &str = "did:web:alice.example";
const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
const DEVICE_AUTHORIZE_EVENT: &str = "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD";
const REALM_ID: &str = "ak:realm:ASlHbbnJj2aIvNxwyukjGz90ltQwXHCbjIihxsRDrRR5";

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
) -> anyhow::Result<KeyBackup> {
    build_passphrase_kdf_backup_body(
        backup_id,
        actor_id,
        device_id,
        root,
        plaintext,
        BackupKind::SecretStorage,
        "recovery_vault",
        &KeyBackupContentItem {
            item_kind: "private_account_state".to_owned(),
            secret_id: Some("inkson_recovery_vault_payload".to_owned()),
            ..Default::default()
        },
    )
}

fn wire(body: &KeyBackup) -> Value {
    serde_json::to_value(body).expect("key backup must serialize at the wire test boundary")
}

fn plaintext_secret(plaintext: &arkret_sdk::KeyBackupPlaintext) -> Vec<u8> {
    B64.decode(plaintext.items[0].secret_b64u.as_bytes())
        .unwrap()
}

fn validate_wire_envelope(body: &Value, expected_kind: BackupKind) -> Result<KeyBackup, String> {
    let envelope: KeyBackup =
        serde_json::from_value(body.clone()).map_err(|error| error.to_string())?;
    if envelope.backup_kind != expected_kind {
        return Err(format!(
            "expected backup kind {}, got {}",
            expected_kind.as_str(),
            envelope.backup_kind.as_str()
        ));
    }
    envelope
        .validate_envelope_fields()
        .map_err(|error| error.to_string())?;
    Ok(envelope)
}

fn sign_test_backup(
    body: KeyBackup,
    signing_key: &SigningKey,
    verification_method: &str,
) -> KeyBackup {
    let auth = arkret_sdk::UnsignedKeyBackupAuthData::new(
        arkret_sdk::DeviceId::new(DEVICE.to_owned()).unwrap(),
        arkret_sdk::DidUrl::new(verification_method.to_owned()).unwrap(),
        arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
        arkret_sdk::EventId::new(DEVICE_AUTHORIZE_EVENT.to_owned()).unwrap(),
    )
    .unwrap();
    let unsigned = arkret_sdk::UnsignedKeyBackup::new(body, auth).unwrap();
    let signature = signing_key.sign(&unsigned.signing_payload_bytes().unwrap());
    unsigned
        .attach_signature(
            arkret_sdk::Base64UrlString::new(B64.encode(signature.to_bytes())).unwrap(),
        )
        .unwrap()
}

#[test]
fn managed_agent_pcr_binding_is_bound_into_hpke_aad() {
    let controller = arkret_sdk::DidFullId::new(ACTOR).unwrap();
    let binding = ManagedPrincipalBinding {
        managed_principal_id: crate::mls_api_helpers::principal_core_id("did:web:agent.example")
            .unwrap(),
        controller_id: arkret_sdk::project_full_id_to_core_id(&controller).unwrap(),
        principal_control_realm_id: arkret_sdk::RealmId::new(
            "ak:realm:ASlHbbnJj2aIvNxwyukjGz90ltQwXHCbjIihxsRDrRR5",
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
        BackupKind::MlsHistory,
        "managed_agent_pcr",
        &KeyBackupContentItem {
            item_kind: "mls_group_state".to_owned(),
            secret_id: Some("inkson_managed_agent_pcr_snapshot".to_owned()),
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
        body.domain_separation.aead_aad.managed_principal_bindings,
        vec![binding]
    );
}

#[test]
fn build_recovery_vault_backup_body_seals_per_spec() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"vault payload")
        .unwrap();
    let body = wire(&body);
    assert_eq!(body["backup_kind"], "secret_storage");
    assert!(
        arkret_sdk::BackupSeriesId::new(body["series_id"].as_str().unwrap().to_owned()).is_ok()
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
    assert!(
        B64.decode(body["encryption"]["kdf"]["salt"].as_str().unwrap())
            .is_ok()
    );
    assert_eq!(body["encryption"]["aead"]["name"], "xchacha20_poly1305");
    assert_eq!(
        body["encryption"]["aead"]["aead_profile"],
        "ak.aead.xchacha20_poly1305.v1"
    );
    assert!(
        B64.decode(body["encryption"]["aead"]["nonce"].as_str().unwrap())
            .is_ok()
    );
    // Spec §7.5 additions: nonce_salt + key_commitment present.
    assert!(
        B64.decode(body["encryption"]["aead"]["nonce_salt"].as_str().unwrap())
            .is_ok()
    );
    assert!(arkret_sdk::Hash::new(body["encryption"]["key_commitment"].as_str().unwrap()).is_ok());
    assert_eq!(body["contents"][0]["item_kind"], "private_account_state");
    assert!(B64.decode(body["ciphertext"].as_str().unwrap()).is_ok());
    assert_eq!(body["device_id"], DEVICE);
    assert_eq!(
        body["domain_separation"]["hkdf_info"],
        "arkret-key-backup/secret_storage/recovery_vault/v1"
    );
    let envelope = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect("secret_storage recovery vault envelope should validate");
    assert_eq!(envelope.backup_id.as_str(), BACKUP_ID);
}

#[test]
fn key_backup_auth_data_sign_verify_round_trip() {
    let root = test_root();
    let body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let vm = format!("{ACTOR}#cx_device_01964137");
    let body = sign_test_backup(body, &signing_key, &vm);

    let auth_data = body.auth_data.as_ref().unwrap();
    assert_eq!(auth_data.verification_method.as_str(), vm);
    assert_eq!(
        auth_data.signature_algorithm,
        arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519
    );
    assert_eq!(
        auth_data.device_authorize_event_id.as_str(),
        DEVICE_AUTHORIZE_EVENT
    );
    body.validate()
        .expect("SDK owns the canonical signed-fields set");

    verify_key_backup_auth_data(&body, &signing_key.verifying_key())
        .expect("freshly signed backup must verify");
}

#[test]
fn key_backup_auth_data_sign_verify_service_attested_round_trip() {
    let root = test_root();
    let body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    let signing_key = SigningKey::from_bytes(&[44u8; 32]);
    let body = sign_test_backup(body, &signing_key, "did:web:a#device");

    assert_eq!(
        body.auth_data
            .as_ref()
            .unwrap()
            .device_authorize_event_id
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
    body.recovery_policy_ref = Some(arkret_sdk::RecoveryPolicyRef {
        policy_id: arkret_sdk::PolicyId::new(
            "ak:policy:01964137-0000-7000-8000-0000000000aa".to_owned(),
        )
        .unwrap(),
        policy_version: 3,
    });
    let signing_key = SigningKey::from_bytes(&[43u8; 32]);
    let body = sign_test_backup(body, &signing_key, "did:web:a#device");
    let signed = &body.auth_data.as_ref().unwrap().signed_fields;
    assert!(
        signed.iter().any(|field| field == "recovery_policy_ref"),
        "recovery_policy_ref must be signed: {signed:?}"
    );
    verify_key_backup_auth_data(&body, &signing_key.verifying_key())
        .expect("signed backup with recovery_policy_ref must verify");
}

#[test]
fn direct_key_backup_signing_is_self_verifying() {
    // The build-path integration uses the process-wide signer slot, which
    // races with other tests; the signing CORRECTNESS is covered by the
    // round-trip/tamper tests. Here we just confirm the direct signing
    // helper produces a self-verifying envelope (deterministic, no globals).
    let root = test_root();
    let body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    let signing_key = SigningKey::from_bytes(&[55u8; 32]);
    let body = sign_test_backup(body, &signing_key, "did:web:alice.example#device");
    verify_key_backup_auth_data(&body, &signing_key.verifying_key())
        .expect("built+signed backup must self-verify");
}

#[test]
fn key_backup_auth_data_rejects_tamper_and_wrong_key() {
    let root = test_root();
    let body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let body = sign_test_backup(body, &signing_key, "did:web:a#device");

    // Tamper a signed field (ciphertext is covered via ciphertext_digest, but
    // mutate backup_kind which is in signed_fields) → verify fails.
    let mut tampered = body.clone();
    tampered.backup_kind = BackupKind::MlsHistory;
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
    let body = wire(&body);
    let recovered =
        open_passphrase_kdf_backup_body(b"correct horse battery staple", &body).unwrap();
    assert_eq!(plaintext_secret(&recovered), b"secret payload");
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
    let mut body = wire(&body);
    // Sanity: the untampered body opens with the correct passphrase.
    assert_eq!(
        plaintext_secret(
            &open_passphrase_kdf_backup_body(b"correct horse battery staple", &body).unwrap()
        ),
        b"secret payload"
    );

    // Re-seal a DIFFERENT plaintext under a fresh context to get a valid but
    // unrelated ciphertext, then splice it in WITHOUT updating the envelope's
    // `ciphertext_digest`. This models an attacker substituting the ciphertext
    // while leaving the signed/declared digest intact.
    let other =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"attacker payload")
            .unwrap();
    let other = wire(&other);
    body["ciphertext"] = other["ciphertext"].clone();
    let err = open_passphrase_kdf_backup_body(b"correct horse battery staple", &body)
        .expect_err("digest mismatch must refuse decryption");
    assert!(
        err.to_string().contains("ciphertext_digest mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn key_backup_validator_rejects_cross_domain_item_mix() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    body["contents"][0]["item_kind"] = json!("mls_group_state");
    attach_key_backup_domain_separation(&mut body, BackupKind::SecretStorage, "recovery_vault");

    let err = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect_err("secret_storage must not carry MLS history items");
    assert!(err.contains("not allowed"));
}

#[test]
fn key_backup_validator_rejects_recipient_method_aad_mismatch() {
    // SEC-04: the AAD's recipient_method binding must agree with the envelope's
    // encryption.recipient_method. Swapping the method after sealing (without
    // recomputing the AAD) MUST be rejected.
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    // Sanity: as-built (passphrase_kdf) it validates and its AAD pins the method.
    validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect("freshly built recovery vault backup validates");
    assert_eq!(
        body["domain_separation"]["aead_aad"]["recipient_method"],
        json!("passphrase_kdf"),
        "AAD must bind the recipient_method"
    );
    // Tamper the AAD's recipient_method so it disagrees with
    // encryption.recipient_method → the SEC-04 cross-check must reject it.
    body["domain_separation"]["aead_aad"]["recipient_method"] = json!("recovery_public_key");
    let err = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect_err("recipient_method/AAD mismatch must be rejected");
    assert!(
        err.contains("authenticated domain metadata mismatch"),
        "{err}"
    );
}

#[test]
fn key_backup_validator_rejects_missing_domain_separation() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    body.as_object_mut().unwrap().remove("domain_separation");

    let err = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect_err("domain separation metadata is required");
    assert!(err.contains("domain_separation"));
}

#[test]
fn key_backup_validator_rejects_missing_series_fields() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    body.as_object_mut().unwrap().remove("series_id");

    let err = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect_err("series_id is mandatory");
    assert!(err.contains("series_id"));
}

#[test]
fn mls_history_rejects_passphrase_kdf() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    body["backup_kind"] = json!("mls_history");
    body["contents"][0]["item_kind"] = json!("mls_group_state");
    attach_key_backup_domain_separation(&mut body, BackupKind::MlsHistory, "mls_snapshot");

    let err = validate_wire_envelope(&body, BackupKind::MlsHistory)
        .expect_err("MLS history passphrase KDF backup must be rejected");
    assert!(err.contains("passphrase_kdf"));
}

#[test]
fn mls_history_accepts_secret_storage_key() {
    let envelope = crate::mls::persistence::encrypt_state(
        REALM_ID,
        "group-a",
        3,
        b"opaque sdk state",
        "device-secret",
        b"salt",
    );
    let body = envelope
        .to_key_backup_body(
            "ak:backup:01964137-0000-7000-8000-00000000feed",
            ACTOR,
            DEVICE,
            &crate::mls::runtime::derive_mls_history_backup_key("device-secret").unwrap(),
        )
        .unwrap();
    assert_eq!(
        body.encryption.recipient_method,
        arkret_sdk::KeyBackupRecipientMethod::SecretStorageKey
    );
    assert_eq!(
        body.encryption.recipient_key_ref.as_deref(),
        Some("mls_group_secrets_backup_key")
    );
    validate_wire_envelope(&wire(&body), BackupKind::MlsHistory)
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
        BackupKind::MlsHistory,
        "mls_snapshot",
        &KeyBackupContentItem {
            item_kind: "mls_group_state".to_owned(),
            secret_id: Some("inkson_mls_snapshot".to_owned()),
            ..Default::default()
        },
        b"opaque mls snapshot bytes",
        Some(("ak:policy:01964137-0000-7000-8000-000000000077", 1)),
    )
    .unwrap();

    let wire_body = wire(&body);

    assert_eq!(
        body.encryption.recipient_method,
        arkret_sdk::KeyBackupRecipientMethod::RecoveryPublicKey
    );
    assert_eq!(
        body.encryption.recipient_key_ref.as_deref(),
        Some("did:web:alice.example#recovery")
    );
    assert!(body.encryption.aead.nonce.is_none());
    validate_wire_envelope(&wire_body, BackupKind::MlsHistory)
        .expect("recovery_public_key mls_history envelope should validate");

    // The recovery private key opens it (the fresh-device restore path);
    // a different recovery key cannot.
    let opened = open_recovery_public_key_backup_body(&sk, &wire_body).unwrap();
    assert_eq!(plaintext_secret(&opened), b"opaque mls snapshot bytes");
    let (other_sk, _other_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    assert!(open_recovery_public_key_backup_body(&other_sk, &wire_body).is_err());
}

#[test]
fn mls_history_rejects_obvious_plaintext_fields() {
    let envelope = crate::mls::persistence::encrypt_state(
        REALM_ID,
        "group-a",
        3,
        b"not real sdk state",
        "device-secret",
        b"salt",
    );
    let body = envelope
        .to_key_backup_body(
            "ak:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            &crate::mls::runtime::derive_mls_history_backup_key("device-secret").unwrap(),
        )
        .unwrap();
    let mut body = wire(&body);
    body["serialized_state"] = json!("plaintext sdk bytes");

    let err = validate_wire_envelope(&body, BackupKind::MlsHistory)
        .expect_err("MLS history backups must stay opaque");
    assert!(err.contains("extension keys must match"), "{err}");
}

#[test]
fn key_backup_validator_rejects_weak_argon2id() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    // Force the wire params below the profile floor (the builder always uses
    // the strong root params, so weaken them post-build to exercise the
    // validator).
    body["encryption"]["kdf"]["params"]["memory_kib"] = json!(1);
    body["encryption"]["kdf"]["params"]["iterations"] = json!(1);

    let err = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect_err("weak KDF parameters must be rejected");
    assert!(err.contains("argon2id"));
}

#[test]
fn key_backup_put_request_rejects_path_body_mismatch() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();

    let path_backup_id =
        arkret_sdk::BackupId::new("ak:backup:01964137-0000-7000-8000-00000000badd".to_owned())
            .unwrap();
    assert_ne!(body.backup_id, path_backup_id);
}

/// The §7.8.1 proof covers the canonical delete-intent transcript the *service*
/// fixed, and tampering with any transcript field after signing breaks it. The
/// two cases below are the ones the client controls: `reason` travels beside the
/// proof in the request body, and an absent reason MUST encode as JSON `null`
/// rather than be omitted, so "no reason" and "reason removed in flight" cannot
/// hash to the same bytes.
#[test]
fn delete_proof_binds_the_reason_it_was_signed_with() {
    let challenge = delete_challenge();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let created_at = challenge.issued_at;

    let with_reason = key_backup_delete_principal_signing_proof(
        &challenge,
        Some("user_requested"),
        "did:web:alice.example#cx_principal_signing_v1",
        &key,
        created_at,
    )
    .expect("proof builds");
    let without_reason = key_backup_delete_principal_signing_proof(
        &challenge,
        None,
        "did:web:alice.example#cx_principal_signing_v1",
        &key,
        created_at,
    )
    .expect("proof builds");

    let (
        arkret_sdk::KeyBackupDeleteProof::PrincipalSigning { proof: signed },
        arkret_sdk::KeyBackupDeleteProof::PrincipalSigning { proof: unsigned },
    ) = (&with_reason, &without_reason)
    else {
        panic!("both are principal_signing proofs");
    };
    assert_ne!(
        signed.payload_digest, unsigned.payload_digest,
        "the reason is inside the signed transcript"
    );
    assert_ne!(signed.jws, unsigned.jws);
    assert_eq!(
        signed.payload_digest,
        challenge
            .delete_intent_digest(Some("user_requested"))
            .expect("digest"),
        "the proof must cover the challenge's own transcript, not a locally derived one"
    );
}

/// `created_at` outside the challenge window is rejected locally rather than
/// sent: the receiver enforces the same window, and a clock-skewed client that
/// discovers this server-side has already burned the challenge.
#[test]
fn delete_proof_refuses_to_sign_outside_the_challenge_window() {
    let challenge = delete_challenge();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    for created_at in [
        challenge.issued_at - chrono::Duration::seconds(1),
        challenge.expires_at + chrono::Duration::seconds(1),
    ] {
        let error = key_backup_delete_principal_signing_proof(
            &challenge,
            None,
            "did:web:alice.example#cx_principal_signing_v1",
            &key,
            created_at,
        )
        .expect_err("outside the window must not produce a proof");
        assert!(error.to_string().contains("challenge window"), "{error}");
    }
}

fn delete_challenge() -> arkret_sdk::KeysBackupsDeleteChallenge {
    let issued_at = chrono::DateTime::from_timestamp(1_800_000_000, 0).expect("timestamp");
    arkret_sdk::KeysBackupsDeleteChallenge {
        challenge_id: arkret_sdk::Base64UrlString::new("Y2hhbGxlbmdlLWlk").unwrap(),
        challenge: arkret_sdk::Base64UrlString::new("Y2hhbGxlbmdl").unwrap(),
        nonce: arkret_sdk::Base64UrlString::new("bm9uY2U").unwrap(),
        operation: arkret_sdk::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE.to_owned(),
        principal_id: crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        backup_id: arkret_sdk::BackupId::new(
            "ak:backup:01964137-0000-7000-8000-00000000beef".to_owned(),
        )
        .unwrap(),
        audience: arkret_sdk::NonEmptyString::new("https://soland.example").unwrap(),
        service_id: crate::mls_api_helpers::principal_core_id("did:web:soland.example").unwrap(),
        request_id: arkret_sdk::Base64UrlString::new("cmVxdWVzdC1pZA").unwrap(),
        issued_at,
        expires_at: issued_at + chrono::Duration::seconds(300),
    }
}
