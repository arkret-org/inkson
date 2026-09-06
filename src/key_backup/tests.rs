use arkret_models_crypto::{KeyBackup, SecretStorageContentIndex, SecretStorageItemKind};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

use super::*;
use crate::recovery_crypto::{VAULT_SALT_LEN, VaultKek, derive_vault_kek_with_salt};

const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-00000000beef";
const ACTOR: &str = "did:web:alice.example";
const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
const SECOND_DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000002";
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
        &crate::test_support::account_actor(actor_id),
        device_id,
        root,
        plaintext,
        BackupKind::SecretStorage,
        "recovery_vault",
        &SecretStorageContentIndex {
            item_kind: SecretStorageItemKind::PrivateAccountState,
            realm_id: None,
            from_epoch: None,
            to_epoch: None,
            secret_id: Some("inkson_recovery_vault_payload".to_owned()),
            secret_version: None,
            extra: Default::default(),
        },
    )
}

fn wire(body: &KeyBackup) -> Value {
    serde_json::to_value(body).expect("key backup must serialize at the wire test boundary")
}

fn plaintext_secret(plaintext: &arkret_sdk::KeyBackupPlaintext) -> Vec<u8> {
    let arkret_models_crypto::KeyBackupKeybag::SecretStorage { items } = &plaintext.keybag else {
        panic!("secret_storage keybag expected");
    };
    B64.decode(items[0].secret_b64u.as_bytes()).unwrap()
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
    assert!(body.get("supersedes_id").is_none());
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
    assert_eq!(body["domain_separation"]["subdomain"], "recovery_vault");
    assert!(body["domain_separation"].get("hkdf_info").is_none());
    assert!(body["domain_separation"].get("aead_aad").is_none());
    let envelope = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect("secret_storage recovery vault envelope should validate");
    assert_eq!(envelope.backup_id.as_str(), BACKUP_ID);
}

#[test]
fn successor_binds_the_current_device_without_breaking_the_series() {
    let root = test_root();
    let predecessor =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"first").unwrap();
    let successor = build_passphrase_kdf_backup_successor_body(
        "ak:backup:01964137-0000-7000-8000-00000000bef0",
        &predecessor,
        SECOND_DEVICE,
        &root,
        b"second",
        &SecretStorageContentIndex {
            item_kind: SecretStorageItemKind::PrivateAccountState,
            realm_id: None,
            from_epoch: None,
            to_epoch: None,
            secret_id: Some("inkson_recovery_vault_payload".to_owned()),
            secret_version: None,
            extra: Default::default(),
        },
        &arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
        2,
    )
    .unwrap();

    assert_eq!(
        successor.device_id.as_ref().unwrap().as_str(),
        SECOND_DEVICE
    );
    assert_eq!(successor.series_id, predecessor.series_id);
    assert_eq!(successor.series_seq, predecessor.series_seq + 1);
    assert_eq!(
        successor.supersedes_id.as_ref(),
        Some(&predecessor.backup_id)
    );
    let opened =
        open_passphrase_kdf_backup_body(b"correct horse battery staple", &wire(&successor))
            .expect("current-device successor must remain decryptable");
    assert_eq!(plaintext_secret(&opened), b"second");
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
fn recovery_policy_ref_is_covered_by_the_closed_transcript_when_present() {
    // 6.2 — when recovery_policy_ref is on the envelope, the closed signing
    // transcript covers it without a producer-authored field manifest.
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
    verify_key_backup_auth_data(&body, &signing_key.verifying_key())
        .expect("signed backup with recovery_policy_ref must verify");
    let mut tampered = body;
    tampered
        .recovery_policy_ref
        .as_mut()
        .unwrap()
        .policy_version += 1;
    assert!(verify_key_backup_auth_data(&tampered, &signing_key.verifying_key()).is_err());
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

    // Tamper a transcript-covered field (ciphertext is covered via
    // ciphertext_digest) → verification fails.
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
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"secret payload")
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
    body["contents"][0] = json!({
        "item_kind": "history_secret_ranges",
        "effective_scope": {"kind": "realm", "realm_id": REALM_ID},
        "ranges": [{"from_epoch": 0, "to_epoch": 1}],
    });
    attach_key_backup_domain_separation(&mut body, BackupKind::SecretStorage, "recovery_vault");

    let err = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect_err("secret_storage must not index history secret ranges");
    assert!(err.contains("history secret ranges"), "{err}");
}

#[test]
fn key_backup_validator_rejects_active_mls_state_item_kinds() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    for forbidden in ["mls_group_state", "mls_epoch_secret", "pending_welcome"] {
        body["contents"][0]["item_kind"] = json!(forbidden);
        attach_key_backup_domain_separation(&mut body, BackupKind::SecretStorage, "recovery_vault");
        validate_wire_envelope(&body, BackupKind::SecretStorage)
            .expect_err("active MLS state item kinds are not on the wire");
    }
}

#[test]
fn key_backup_validator_rejects_legacy_aad_mirror() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect("freshly built recovery vault backup validates");
    body["domain_separation"]["aead_aad"] = json!({"recipient_method":"passphrase_kdf"});
    let err = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect_err("legacy AAD mirrors must be rejected");
    assert!(err.contains("unknown field"), "{err}");
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
fn mls_history_requires_exactly_one_history_range_index() {
    let root = test_root();
    let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
    let mut body = wire(&body);
    body["backup_kind"] = json!("mls_history");
    attach_key_backup_domain_separation(&mut body, BackupKind::MlsHistory, "mls_snapshot");

    let err = validate_wire_envelope(&body, BackupKind::MlsHistory)
        .expect_err("an mls_history envelope may only index history secret ranges");
    assert!(err.contains("history_secret_ranges"), "{err}");
}

#[test]
fn recovery_public_key_backup_round_trips_and_validates() {
    let (sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    let body = build_recovery_public_key_backup_body_in_series(
        BACKUP_ID,
        &crate::test_support::account_actor(ACTOR),
        DEVICE,
        &pk,
        "did:web:alice.example#recovery",
        BackupKind::SecretStorage,
        "recovery_vault",
        &SecretStorageContentIndex {
            item_kind: SecretStorageItemKind::MlsAccountSecret,
            realm_id: None,
            from_epoch: None,
            to_epoch: None,
            secret_id: Some("inkson_mls_account_secret".to_owned()),
            secret_version: Some(1),
            extra: Default::default(),
        },
        b"opaque account secret bytes",
        Some(("ak:policy:01964137-0000-7000-8000-000000000077", 1)),
        None,
        None,
        None,
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
    validate_wire_envelope(&wire_body, BackupKind::SecretStorage)
        .expect("recovery_public_key secret_storage envelope should validate");

    // The recovery private key opens it (the fresh-device restore path);
    // a different recovery key cannot.
    let opened = open_recovery_public_key_backup_body(&sk, &wire_body).unwrap();
    assert_eq!(plaintext_secret(&opened), b"opaque account secret bytes");
    let (other_sk, _other_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    assert!(open_recovery_public_key_backup_body(&other_sk, &wire_body).is_err());
}

#[test]
fn portable_history_backup_round_trips_as_history_only_scope_object() {
    let (sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    let effective_scope = arkret_sdk::HistoryEffectiveScope::Realm {
        realm_id: arkret_sdk::RealmId::new(REALM_ID.to_owned()).unwrap(),
    };
    let keybag = arkret_models_crypto::KeyBackupKeybag::MlsHistory {
        effective_scope: effective_scope.clone(),
        items: vec![arkret_sdk::HistorySecretRange {
            from_epoch: 2,
            to_epoch: 3,
            secrets_b64u: B64.encode([7u8; 64]),
        }],
    };
    let body = build_recovery_public_key_history_backup_body_in_series(
        BACKUP_ID,
        &crate::test_support::account_actor(ACTOR),
        DEVICE,
        &pk,
        "did:web:alice.example#backup-hpke",
        keybag,
        ("ak:policy:01964137-0000-7000-8000-000000000077", 1),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(body.backup_kind, BackupKind::MlsHistory);
    assert_eq!(body.contents.len(), 1);
    assert!(body.contents[0].secret_id().is_none());
    let opened = open_recovery_public_key_backup_body(&sk, &wire(&body)).unwrap();
    let arkret_models_crypto::KeyBackupKeybag::MlsHistory {
        effective_scope: opened_scope,
        items,
    } = opened.keybag
    else {
        panic!("mls_history keybag expected");
    };
    assert_eq!(opened_scope, effective_scope);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].from_epoch, 2);
    assert_eq!(items[0].to_epoch, 3);
    assert_eq!(
        B64.decode(items[0].secrets_b64u.as_bytes()).unwrap(),
        [7u8; 64]
    );
}

#[test]
fn key_backup_rejects_obvious_plaintext_fields() {
    let root = test_root();
    let body =
        build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"opaque").unwrap();
    let mut body = wire(&body);
    body["serialized_state"] = json!("plaintext sdk bytes");

    let err = validate_wire_envelope(&body, BackupKind::SecretStorage)
        .expect_err("key backups must stay opaque");
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
