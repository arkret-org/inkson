use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::Signer as _;
use garth::mls::backup_selection::{
    is_mls_account_secret_backup, is_mls_private_plaintext_backup,
    mls_account_secret_backup_version, select_mls_account_secret_backup,
    select_mls_account_secret_recovery_public_key_backup, select_mls_history_backups,
    select_mls_private_plaintext_backup, select_preferred_mls_account_secret_backup,
};
use garth::mls::backup_series::{backup_series_seq, verify_series_chain};
use serde_json::Value;

use super::backup_body::{
    MLS_ACCOUNT_SECRET_ITEM_KIND, MLS_ACCOUNT_SECRET_SECRET_ID, MLS_PRIVATE_PLAINTEXT_ITEM_KIND,
    MLS_PRIVATE_PLAINTEXT_SECRET_ID, build_mls_account_secret_backup_body_with_kek,
    build_mls_account_secret_backup_successor_body_with_kek_and_version,
    build_mls_account_secret_recovery_public_key_backup,
    build_mls_account_secret_recovery_public_key_backup_in_series,
    build_mls_private_plaintext_backup_body_with_kek, decrypt_mls_account_secret_backup,
    decrypt_mls_private_plaintext_backup,
};
use super::restore::{mls_backup_prompt_required, verify_active_backup_series};
use crate::key_backup::BackupKind;
use crate::recovery_crypto::derive_vault_kek;
use crate::secure_key_store::MemorySecureKeyStore;

const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-00000000beef";
const SIDECAR_BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-00000000cafe";
const ACTOR: &str = "did:web:alice.example";
const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
const PASSPHRASE: &[u8] = b"correct horse battery staple";
const ACCOUNT_SECRET: &str = "qr6h9rJ8nU0H2pP5w3sLx1A4bC7dE9fG2hI5jK8lM0N";
const ACTIVE_SECRET_STORAGE_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-0000000000a1";
const STALE_SECRET_STORAGE_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-0000000000a2";
const ACTIVE_MLS_HISTORY_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-0000000000b1";

fn authority() -> arkret_sdk::AccountId {
    crate::test_support::authority_at_station(ACTOR, crate::test_support::SERVER_STATION_ID)
}

fn backup_frontier_ref() -> arkret_sdk::KeyBackupFrontierRef {
    arkret_sdk::KeyBackupFrontierRef {
        frontier_digest: arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        seal_ref: Some(format!("ak:seal:sha256:{}", "b".repeat(64))),
        device_generation_ref: 1,
    }
}

fn key_backup_wire(body: &arkret_sdk::KeyBackup) -> Value {
    serde_json::to_value(body).expect("key backup must serialize at the wire test boundary")
}

fn validate_wire_envelope(body: &Value, expected_kind: BackupKind) -> Result<(), String> {
    let envelope: arkret_sdk::KeyBackup =
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
        .map_err(|error| error.to_string())
}

fn sign_wire_envelope(body: Value) -> Value {
    let mut envelope: arkret_sdk::KeyBackup = serde_json::from_value(body).unwrap();
    envelope.auth_data = None;
    let device_id = envelope.device_id.clone().unwrap();
    let auth = arkret_sdk::UnsignedKeyBackupAuthData::new(
        device_id,
        arkret_sdk::DidUrl::new(format!("{ACTOR}#test-device")).unwrap(),
        arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
        arkret_sdk::EventId::new(
            "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD".to_owned(),
        )
        .unwrap(),
    )
    .unwrap();
    let unsigned = arkret_sdk::UnsignedKeyBackup::new(envelope, auth).unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32]);
    let signature = signing_key.sign(&unsigned.signing_payload_bytes().unwrap());
    key_backup_wire(
        &unsigned
            .attach_signature(
                arkret_sdk::Base64UrlString::new(B64.encode(signature.to_bytes())).unwrap(),
            )
            .unwrap(),
    )
}

fn wrap() -> Value {
    let kek = derive_vault_kek(PASSPHRASE).unwrap();
    sign_wire_envelope(key_backup_wire(
        &build_mls_account_secret_backup_body_with_kek(
            BACKUP_ID,
            ACTOR,
            DEVICE,
            &kek,
            ACCOUNT_SECRET,
        )
        .unwrap(),
    ))
}

/// Build the HPKE `recovery_public_key` account-secret backup that the
/// recovery-public-key design treats as the preferred, passphrase-free
/// recovery material. The prompt gates (`mls_restore_prompt_required` /
/// `mls_backup_prompt_required`) key off this body, not the passphrase-wrapped
/// `wrap()` `secret_storage` body.
fn recovery_hpke_backup() -> Value {
    let (_sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    sign_wire_envelope(key_backup_wire(
        &build_mls_account_secret_recovery_public_key_backup(
            "ak:backup:01964137-0000-7000-8000-00000000c0de",
            ACTOR,
            DEVICE,
            &pk,
            "did:web:alice.example#recovery",
            ACCOUNT_SECRET,
            1,
            ("ak:policy:01964137-0000-7000-8000-0000000000a1", 3),
        )
        .unwrap(),
    ))
}

fn active_series_record(backup_kind: &str, active_series_id: &str) -> Value {
    serde_json::json!({
        "schema": SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1,
        "actor_id": arkret_sdk::ActorId::account(authority()),
        "backup_kind": backup_kind,
        "active_series_id": active_series_id,
        "series_pointer_version": 1,
        "previous_series_ids": [],
    })
}

fn backup_series_id(body: &Value) -> &str {
    body.get("series_id")
        .and_then(Value::as_str)
        .expect("backup must carry a series_id")
}

fn payload_with_inferred_active_series(backups: Vec<Value>) -> Value {
    let active_series = ["secret_storage", "mls_history"]
        .into_iter()
        .filter_map(|backup_kind| {
            backups
                .iter()
                .find(|body| {
                    body.get("backup_kind").and_then(Value::as_str) == Some(backup_kind)
                        && body.get("series_id").and_then(Value::as_str).is_some()
                })
                .map(|body| active_series_record(backup_kind, backup_series_id(body)))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "active_series": active_series,
        "backups": backups,
    })
}

use arkret_wire::SchemaId;

#[test]
fn active_series_restore_preserves_station_scoped_rollback_floors() {
    let mut state = crate::state::isolated_store_for_tests("backup-actor-floors");
    let alpha = authority();
    let beta = arkret_sdk::AccountId::new(
        alpha.principal_id.clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:beta.example").unwrap(),
    );
    let payload = |account: &arkret_sdk::AccountId, version| {
        serde_json::json!({
            "active_series": [{
                "actor_id": arkret_sdk::ActorId::account(account.clone()),
                "backup_kind": "secret_storage",
                "series_pointer_version": version,
            }],
            "backups": [],
        })
    };
    super::restore::observe_active_series_versions(&payload(&alpha, 5), &mut state, &alpha, ACTOR)
        .unwrap();
    super::restore::observe_active_series_versions(&payload(&beta, 1), &mut state, &beta, ACTOR)
        .unwrap();
    assert_eq!(state.load().key_backup_active_series_highest_seen.len(), 2);
    let error = super::restore::observe_active_series_versions(
        &payload(&alpha, 4),
        &mut state,
        &alpha,
        ACTOR,
    )
    .unwrap_err();
    assert!(error.to_string().contains("backup_frontier_stale"));
}

#[test]
fn active_series_restore_rejects_foreign_station_and_scalar_actors() {
    let mut state = crate::state::isolated_store_for_tests("backup-actor-binding");
    let account = authority();
    let foreign = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        account.principal_id.clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
    ));
    for actor in [serde_json::json!(foreign), serde_json::json!(ACTOR)] {
        let mut payload = serde_json::json!({
            "active_series": [active_series_record("secret_storage", ACTIVE_SECRET_STORAGE_SERIES)],
            "backups": [],
        });
        payload["active_series"][0]["actor_id"] = actor.clone();
        assert!(
            super::restore::observe_active_series_versions(&payload, &mut state, &account, ACTOR,)
                .is_err()
        );
        payload["active_series"][0]["actor_id"] =
            serde_json::json!(arkret_sdk::ActorId::account(account.clone()));
        payload["backups"] = serde_json::json!([{ "actor_id": actor }]);
        assert!(
            super::restore::observe_active_series_versions(&payload, &mut state, &account, ACTOR,)
                .is_err()
        );
        assert!(
            state
                .load()
                .key_backup_active_series_highest_seen
                .is_empty()
        );
    }
}

#[test]
fn wrap_then_unwrap_round_trips_the_secret() {
    let body = wrap();
    let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
    assert_eq!(recovered, ACCOUNT_SECRET.as_bytes());
}

#[test]
fn wrong_passphrase_fails_to_unwrap() {
    let body = wrap();
    let result = decrypt_mls_account_secret_backup(b"incorrect horse", &body);
    assert!(result.is_err());
}

#[test]
fn put_body_has_expected_item_identifiers() {
    let body = wrap();
    assert!(is_mls_account_secret_backup(&body));
    assert_eq!(
        body["contents"][0]["item_kind"].as_str(),
        Some(MLS_ACCOUNT_SECRET_ITEM_KIND.as_str())
    );
    assert_eq!(
        body["contents"][0]["secret_id"].as_str(),
        Some(MLS_ACCOUNT_SECRET_SECRET_ID)
    );
    assert_eq!(body["backup_kind"], "secret_storage");
    // item_kind must be one both validators' allowlists accept.
    assert_eq!(MLS_ACCOUNT_SECRET_ITEM_KIND.as_str(), "mls_account_secret");
    assert_eq!(
        mls_account_secret_backup_version(&body),
        crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION
    );
}

#[test]
fn put_body_contains_no_plaintext_secret() {
    let body = wrap();
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains(ACCOUNT_SECRET));
}

#[test]
fn real_encrypt_build_validate_decrypt_round_trips_end_to_end() {
    // No hand-crafted fixtures: this exercises the REAL pipeline —
    // encrypt_vault (which emits base64url) → build the upload body → the
    // SAME key-backup validator the mls_history backup uses → decrypt back
    // to the plaintext secret. encrypt_vault now emits base64url natively,
    // so the validator's base64url charset check on ciphertext/nonce/salt
    // passes for every random ciphertext (no `+`/`/` ever appear).
    let body = wrap();

    // 1. The three wire fields are base64url (only `[A-Za-z0-9-_]`), never STANDARD-base64 `+`/`/`.
    for (label, field) in [
        ("ciphertext", body["ciphertext"].as_str().unwrap()),
        ("salt", body["encryption"]["kdf"]["salt"].as_str().unwrap()),
        (
            "nonce",
            body["encryption"]["aead"]["nonce"].as_str().unwrap(),
        ),
    ] {
        assert!(!field.is_empty(), "{label} must not be empty");
        assert!(
            field
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{label} must be base64url (no `+`/`/`/`=`), got: {field}"
        );
    }

    // 2. The body validates under the exact validator soland-mirroring clients run (the same one
    //    `mls_history` backups must pass).
    validate_wire_envelope(&body, BackupKind::SecretStorage).expect(
        "mls_account_secret backup must validate as a secret_storage envelope (base64url-clean)",
    );

    // 3. The full decrypt path recovers the original secret bytes.
    let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
    assert_eq!(recovered, ACCOUNT_SECRET.as_bytes());
}

#[test]
fn round_trips_even_when_random_bytes_would_need_url_safe_alphabet() {
    // Hammer the encode/decode boundary: across many random salts/nonces
    // and ciphertexts, the produced ciphertext WILL contain bytes that
    // STANDARD base64 renders as `+`/`/`. Every one must validate as
    // base64url-clean; the boundary iterations also exercise full decryption.
    let kek = derive_vault_kek(PASSPHRASE).unwrap();
    for i in 0..32u32 {
        let secret = format!("account-secret-payload-with-entropy-{i:08x}-padding++//");
        let body =
            build_mls_account_secret_backup_body_with_kek(BACKUP_ID, ACTOR, DEVICE, &kek, &secret)
                .unwrap();
        let body = key_backup_wire(&body);

        for field in [
            body["ciphertext"].as_str().unwrap(),
            body["encryption"]["kdf"]["salt"].as_str().unwrap(),
            body["encryption"]["aead"]["nonce"].as_str().unwrap(),
        ] {
            assert!(
                field
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "iteration {i}: field is not base64url-clean: {field}"
            );
        }

        validate_wire_envelope(&body, BackupKind::SecretStorage)
            .unwrap_or_else(|err| panic!("iteration {i}: envelope must validate: {err}"));

        if i == 0 || i == 31 {
            let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
            assert_eq!(recovered, secret.as_bytes(), "iteration {i}: round-trip");
        }
    }
}

#[test]
fn select_account_secret_finds_it_in_a_list_payload() {
    let account_secret_body = wrap();
    // A `list_key_backups`-shaped payload mixing a history backup, an
    // unrelated recovery vault, and the account-secret backup.
    let payload = payload_with_inferred_active_series(vec![
        serde_json::json!({ "backup_id": "ak:backup:a", "backup_kind": "mls_history" }),
        serde_json::json!({
            "backup_id": "ak:backup:b",
            "backup_kind": "recovery",
            "contents": [{ "secret_id": "inkson_recovery_vault_payload" }]
        }),
        account_secret_body.clone(),
    ]);
    let found = select_mls_account_secret_backup(&payload).expect("account secret present");
    assert!(is_mls_account_secret_backup(&found));
    // No-account-secret payload returns None.
    let none_payload = serde_json::json!({
        "backups": [ { "backup_id": "ak:backup:a", "backup_kind": "mls_history" } ]
    });
    assert!(select_mls_account_secret_backup(&none_payload).is_none());
    // Absent/empty payloads are tolerated.
    assert!(select_mls_account_secret_backup(&serde_json::json!({})).is_none());
}

#[test]
fn preferred_account_secret_requires_recovery_public_key() {
    let passphrase_wrapped = wrap();
    let (_sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    let hpke = build_mls_account_secret_recovery_public_key_backup(
        "ak:backup:01964137-0000-7000-8000-00000000c001",
        ACTOR,
        DEVICE,
        &pk,
        "did:web:alice.example#recovery",
        ACCOUNT_SECRET,
        1,
        ("ak:policy:01964137-0000-7000-8000-0000000000a1", 3),
    )
    .unwrap();
    let hpke = key_backup_wire(&hpke);
    let payload = serde_json::json!({
        "active_series": [active_series_record("secret_storage", backup_series_id(&hpke))],
        "backups": [passphrase_wrapped.clone(), hpke.clone()]
    });

    let found = select_preferred_mls_account_secret_backup(&payload)
        .expect("preferred account secret present");
    assert_eq!(
        found["encryption"]["recipient_method"],
        serde_json::json!("recovery_public_key")
    );

    let passphrase_only = payload_with_inferred_active_series(vec![passphrase_wrapped.clone()]);
    assert!(select_preferred_mls_account_secret_backup(&passphrase_only).is_none());
}

#[test]
fn select_account_secret_prefers_highest_series_seq() {
    let mut older = wrap();
    older["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-00000000bee1");
    older["series_seq"] = serde_json::json!(1);
    older["series_id"] = serde_json::json!(ACTIVE_SECRET_STORAGE_SERIES);
    let mut newer = wrap();
    newer["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-00000000bee2");
    newer["series_seq"] = serde_json::json!(2);
    newer["series_id"] = serde_json::json!(ACTIVE_SECRET_STORAGE_SERIES);
    let payload = serde_json::json!({
        "active_series": [
            active_series_record("secret_storage", ACTIVE_SECRET_STORAGE_SERIES)
        ],
        "backups": [newer.clone(), older]
    });

    let found = select_mls_account_secret_backup(&payload).expect("account secret present");

    assert_eq!(found["backup_id"], newer["backup_id"]);
}

#[test]
fn verify_series_chain_accepts_single_genesis() {
    let genesis = wrap();
    assert_eq!(backup_series_seq(&genesis), 0);
    verify_series_chain(&genesis, std::slice::from_ref(&genesis))
        .expect("a lone genesis envelope is a valid one-link chain");
}

#[test]
fn verify_series_chain_rejects_missing_intermediate() {
    // Genesis + a forged seq=2 tail with no seq=1 link present: a withholding
    // server signature that must be rejected.
    let mut genesis = wrap();
    genesis["series_id"] =
        serde_json::json!("ak:backup_series:01964137-0000-7000-8000-0000000000c1");
    genesis["series_seq"] = serde_json::json!(0);
    let mut forged_tail = genesis.clone();
    forged_tail["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000c2");
    forged_tail["series_seq"] = serde_json::json!(2);
    forged_tail["supersedes_id"] = serde_json::json!("ak:backup:does-not-exist");
    forged_tail["supersedes_digest"] = serde_json::json!("sha256:deadbeef");

    let err = verify_series_chain(&forged_tail, &[genesis, forged_tail.clone()])
        .expect_err("a chain missing series_seq 1 must be rejected");
    assert!(err.to_string().contains("series_chain_broken"));
}

#[test]
fn verify_series_chain_accepts_well_formed_successor() {
    let genesis = wrap();
    let predecessor: arkret_sdk::KeyBackup = serde_json::from_value(genesis.clone()).unwrap();
    let frontier = backup_frontier_ref();
    let successor = build_mls_account_secret_backup_successor_body_with_kek_and_version(
        "ak:backup:01964137-0000-7000-8000-0000000000d2",
        &predecessor,
        DEVICE,
        &derive_vault_kek(PASSPHRASE).unwrap(),
        ACCOUNT_SECRET,
        2,
        &frontier.frontier_digest,
        frontier.device_generation_ref,
    )
    .expect("SDK successor builder must seal the final series identity");
    let successor = key_backup_wire(&successor);

    verify_series_chain(&successor, &[genesis, successor.clone()])
        .expect("an SDK-built successor must verify");
    assert_eq!(
        decrypt_mls_account_secret_backup(PASSPHRASE, &successor).unwrap(),
        ACCOUNT_SECRET.as_bytes(),
        "successor plaintext identity must decrypt under its final series metadata"
    );
}

#[test]
fn private_plaintext_successor_is_sealed_with_final_series_metadata() {
    let kek = derive_vault_kek(ACCOUNT_SECRET.as_bytes()).unwrap();
    let genesis = build_mls_private_plaintext_backup_body_with_kek(
        SIDECAR_BACKUP_ID,
        ACTOR,
        DEVICE,
        &kek,
        br#"{"realm":{"strand":{"title":"first"}}}"#,
    )
    .unwrap();
    let frontier = backup_frontier_ref();
    let successor = super::backup_body::build_mls_private_plaintext_backup_successor_body_with_kek(
        "ak:backup:01964137-0000-7000-8000-00000000caf1",
        &genesis,
        DEVICE,
        &kek,
        br#"{"realm":{"strand":{"title":"successor"}}}"#,
        &frontier.frontier_digest,
        frontier.device_generation_ref,
    )
    .unwrap();
    let successor_wire = key_backup_wire(&successor);
    assert_eq!(successor.series_id, genesis.series_id);
    assert_eq!(successor.series_seq, 1);
    assert_eq!(
        decrypt_mls_private_plaintext_backup(ACCOUNT_SECRET.as_bytes(), &successor_wire).unwrap(),
        br#"{"realm":{"strand":{"title":"successor"}}}"#
    );
}

#[test]
fn recovery_public_key_backup_policy_ref_is_enforced_on_open() {
    use super::backup_body::open_mls_account_secret_recovery_public_key_backup;

    let (recovery_sk, recovery_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    // SEC-05: build a backup bound to policy (P1, v3).
    let body = build_mls_account_secret_recovery_public_key_backup(
        BACKUP_ID,
        ACTOR,
        DEVICE,
        &recovery_pk,
        "did:web:alice.example#recovery",
        ACCOUNT_SECRET,
        1,
        ("ak:policy:01964137-0000-7000-8000-0000000000a1", 3),
    )
    .unwrap();
    let body = key_backup_wire(&body);

    // Matching policy → opens.
    let (secret, _version) = open_mls_account_secret_recovery_public_key_backup(
        &recovery_sk,
        &body,
        ("ak:policy:01964137-0000-7000-8000-0000000000a1", 3),
    )
    .unwrap();
    assert_eq!(secret, ACCOUNT_SECRET);

    // Stale policy version → rejected before import.
    assert!(
        open_mls_account_secret_recovery_public_key_backup(
            &recovery_sk,
            &body,
            ("ak:policy:01964137-0000-7000-8000-0000000000a1", 2),
        )
        .is_err(),
        "old policy version must be rejected"
    );

    // Different policy id → rejected.
    assert!(
        open_mls_account_secret_recovery_public_key_backup(
            &recovery_sk,
            &body,
            ("ak:policy:01964137-0000-7000-8000-0000000000a2", 3),
        )
        .is_err(),
        "different policy id must be rejected"
    );
}

#[test]
fn recovery_public_key_successor_is_sealed_with_final_series_metadata() {
    use super::backup_body::open_mls_account_secret_recovery_public_key_backup;

    let (recovery_sk, recovery_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    let recovery_key_ref = "did:web:alice.example#recovery";
    let recovery_policy_ref = ("ak:policy:01964137-0000-7000-8000-0000000000a1", 3);
    let account = authority();
    let genesis = build_mls_account_secret_recovery_public_key_backup_in_series(
        "ak:backup:01964137-0000-7000-8000-00000000c101",
        &account,
        DEVICE,
        &recovery_pk,
        recovery_key_ref,
        ACCOUNT_SECRET,
        1,
        recovery_policy_ref,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        genesis.actor_id,
        arkret_sdk::ActorId::account(account.clone())
    );
    let genesis_wire = key_backup_wire(&genesis);
    let successor = build_mls_account_secret_recovery_public_key_backup_in_series(
        "ak:backup:01964137-0000-7000-8000-00000000c102",
        &account,
        DEVICE,
        &recovery_pk,
        recovery_key_ref,
        ACCOUNT_SECRET,
        2,
        recovery_policy_ref,
        Some(&genesis_wire),
        Some(backup_frontier_ref()),
    )
    .unwrap();

    assert_eq!(&successor.series_id, &genesis.series_id);
    assert_eq!(successor.series_seq, 1);
    assert_eq!(successor.supersedes_id.as_ref(), Some(&genesis.backup_id));
    let successor_wire = key_backup_wire(&successor);
    let (secret, version) = open_mls_account_secret_recovery_public_key_backup(
        &recovery_sk,
        &successor_wire,
        recovery_policy_ref,
    )
    .unwrap();
    assert_eq!(secret, ACCOUNT_SECRET);
    assert_eq!(version, 2);
}

#[test]
fn recovery_public_key_backup_without_policy_ref_rejected_when_policy_expected() {
    use super::backup_body::open_mls_account_secret_recovery_public_key_backup;

    let (recovery_sk, recovery_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    // Backup built WITHOUT a policy ref.
    let body = build_mls_account_secret_recovery_public_key_backup(
        BACKUP_ID,
        ACTOR,
        DEVICE,
        &recovery_pk,
        "did:web:alice.example#recovery",
        ACCOUNT_SECRET,
        1,
        ("ak:policy:01964137-0000-7000-8000-0000000000a1", 3),
    )
    .unwrap();
    let mut body = key_backup_wire(&body);
    body.as_object_mut().unwrap().remove("recovery_policy_ref");
    // SEC-05: with an expected policy and no ref on the envelope → fail closed.
    assert!(
        open_mls_account_secret_recovery_public_key_backup(
            &recovery_sk,
            &body,
            ("ak:policy:01964137-0000-7000-8000-0000000000a1", 3),
        )
        .is_err(),
        "missing recovery_policy_ref must fail closed when a policy is expected"
    );
}

#[test]
fn backup_prompt_not_required_when_no_local_secret() {
    // User never used encryption: no local account secret, server has no
    // backup either. Don't nag.
    let store = MemorySecureKeyStore::new();
    let payload = serde_json::json!({ "backups": [] });
    assert!(!mls_backup_prompt_required(&payload, &store, &authority()));
}

#[test]
fn backup_prompt_required_when_local_secret_and_no_server_backup() {
    // User has used encryption (local secret present) but never backed it
    // up to the server -> prompt them to set a recovery passphrase.
    let store = MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&store, &authority(), ACCOUNT_SECRET).unwrap();
    let payload = serde_json::json!({
        "backups": [ { "backup_id": "ak:backup:a", "backup_kind": "mls_history" } ]
    });
    assert!(mls_backup_prompt_required(&payload, &store, &authority()));
}

#[test]
fn backup_prompt_not_required_when_server_backup_present() {
    // Server already holds the passphrase-free recovery-public-key account-secret
    // backup: fresh-device recovery material exists, so nothing to upload.
    let store = MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&store, &authority(), ACCOUNT_SECRET).unwrap();
    let payload = payload_with_inferred_active_series(vec![recovery_hpke_backup()]);
    assert!(!mls_backup_prompt_required(&payload, &store, &authority()));
}

#[test]
fn select_account_secret_prefers_tail_seq_over_newer_timestamp() {
    // P1 rollback guard: within one series (same secret_version), a low-seq
    // link with a NEWER created_at MUST NOT beat the true higher-seq tail.
    let series = "ak:backup_series:01964137-0000-7000-8000-0000000000e0";
    let mut tail = wrap();
    tail["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000e2");
    tail["series_id"] = serde_json::json!(series);
    tail["series_seq"] = serde_json::json!(2);
    tail["created_at"] = serde_json::json!("2026-01-01T00:00:00.000Z");
    // A resurrected old seq=1 with a LATER timestamp (server injection).
    let mut stale = wrap();
    stale["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000e1");
    stale["series_id"] = serde_json::json!(series);
    stale["series_seq"] = serde_json::json!(1);
    stale["created_at"] = serde_json::json!("2026-12-31T23:59:59.000Z");

    let payload = serde_json::json!({
        "active_series": [active_series_record("secret_storage", series)],
        "backups": [stale, tail.clone()]
    });
    let found = select_mls_account_secret_backup(&payload).expect("account secret present");
    assert_eq!(
        found["backup_id"], tail["backup_id"],
        "higher series_seq tail must win even with an older timestamp"
    );
}

#[test]
fn select_account_secret_honors_active_series_record() {
    let mut active = wrap();
    active["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000a1");
    active["series_id"] = serde_json::json!(ACTIVE_SECRET_STORAGE_SERIES);
    active["series_seq"] = serde_json::json!(0);
    active["created_at"] = serde_json::json!("2026-01-01T00:00:00.000Z");
    active["contents"][0]["secret_version"] = serde_json::json!(1);

    let mut stale = wrap();
    stale["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000a2");
    stale["series_id"] = serde_json::json!(STALE_SECRET_STORAGE_SERIES);
    stale["series_seq"] = serde_json::json!(99);
    stale["created_at"] = serde_json::json!("2026-12-31T23:59:59.000Z");
    stale["contents"][0]["secret_version"] = serde_json::json!(99);

    let payload = serde_json::json!({
        "active_series": [
            active_series_record("secret_storage", ACTIVE_SECRET_STORAGE_SERIES)
        ],
        "backups": [stale, active.clone()]
    });

    let found = select_mls_account_secret_backup(&payload).expect("active account secret present");
    assert_eq!(found["backup_id"], active["backup_id"]);
}

#[test]
fn select_account_secret_fails_closed_when_active_series_is_missing() {
    let mut backup = wrap();
    backup["series_id"] = serde_json::json!(STALE_SECRET_STORAGE_SERIES);
    backup["series_seq"] = serde_json::json!(42);
    backup["contents"][0]["secret_version"] = serde_json::json!(42);
    let payload = serde_json::json!({
        "active_series": [
            active_series_record("secret_storage", ACTIVE_SECRET_STORAGE_SERIES)
        ],
        "backups": [backup]
    });

    assert!(select_mls_account_secret_backup(&payload).is_none());
}

#[test]
fn select_account_secret_infers_the_only_series_without_an_active_record() {
    let backup = wrap();
    let payload = serde_json::json!({
        "active_series": [],
        "backups": [backup.clone()]
    });

    let found = select_mls_account_secret_backup(&payload).expect("unique series is unambiguous");
    assert_eq!(found["backup_id"], backup["backup_id"]);
}

#[test]
fn select_account_secret_rejects_multiple_series_without_an_active_record() {
    let mut first = wrap();
    first["series_id"] = serde_json::json!(ACTIVE_SECRET_STORAGE_SERIES);
    let mut second = wrap();
    second["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000a3");
    second["series_id"] = serde_json::json!(STALE_SECRET_STORAGE_SERIES);
    let payload = serde_json::json!({
        "active_series": [],
        "backups": [first, second]
    });

    assert!(select_mls_account_secret_backup(&payload).is_none());
}

#[test]
fn select_account_secret_accepts_the_only_series_without_a_pointer_projection() {
    let backup = recovery_hpke_backup();
    let payload = serde_json::json!({ "backups": [backup.clone()] });

    let selected = select_mls_account_secret_recovery_public_key_backup(&payload)
        .expect("sole series is unambiguous");
    assert_eq!(selected["backup_id"], backup["backup_id"]);
}

#[test]
fn select_account_secret_rejects_multiple_series_without_a_pointer_projection() {
    let mut first = recovery_hpke_backup();
    first["series_id"] = serde_json::json!(ACTIVE_SECRET_STORAGE_SERIES);
    let mut second = recovery_hpke_backup();
    second["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000f2");
    second["series_id"] = serde_json::json!(STALE_SECRET_STORAGE_SERIES);
    let payload = serde_json::json!({ "backups": [first, second] });

    assert!(select_mls_account_secret_recovery_public_key_backup(&payload).is_none());
}

#[test]
fn verify_account_secret_accepts_the_only_series_without_a_pointer_projection() {
    let payload = serde_json::json!({ "backups": [recovery_hpke_backup()] });

    verify_active_backup_series(&payload, BackupKind::SecretStorage.as_str())
        .expect("sole series is authoritative and must verify");
}

#[test]
fn verify_account_secret_rejects_multiple_series_without_a_pointer_projection() {
    let mut first = recovery_hpke_backup();
    first["series_id"] = serde_json::json!(ACTIVE_SECRET_STORAGE_SERIES);
    let mut second = recovery_hpke_backup();
    second["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000f2");
    second["series_id"] = serde_json::json!(STALE_SECRET_STORAGE_SERIES);
    let payload = serde_json::json!({ "backups": [first, second] });

    assert!(verify_active_backup_series(&payload, BackupKind::SecretStorage.as_str()).is_err());
}

#[test]
fn select_history_backups_filters_by_class() {
    let payload = serde_json::json!({
        "active_series": [
            active_series_record("mls_history", ACTIVE_MLS_HISTORY_SERIES)
        ],
        "backups": [
            { "backup_id": "ak:backup:a", "backup_kind": "mls_history", "series_id": ACTIVE_MLS_HISTORY_SERIES },
            { "backup_id": "ak:backup:b", "backup_kind": "secret_storage" },
            { "backup_id": "ak:backup:c", "backup_kind": "mls_history", "series_id": ACTIVE_MLS_HISTORY_SERIES },
            { "backup_id": "ak:backup:d" },
        ]
    });
    let histories = select_mls_history_backups(&payload);
    assert_eq!(histories.len(), 2);
    assert!(
        histories
            .iter()
            .all(|b| { b.get("backup_kind").and_then(Value::as_str) == Some("mls_history") })
    );
    assert!(select_mls_history_backups(&serde_json::json!({})).is_empty());
}

// ---- X5.3: encrypted private-plaintext sidecar backup ----

fn sample_sidecar() -> std::collections::BTreeMap<
    String,
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
> {
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("body".to_owned(), "\"author body\"".to_owned());
    fields.insert("synthesis".to_owned(), "\"author synthesis\"".to_owned());
    let mut strands = std::collections::BTreeMap::new();
    strands.insert(
        "ak:strand:Ag0CE2EBjaYARZ8GMXa7liKkM90gtiQk9wVadXyPVDyc".to_owned(),
        fields,
    );
    let mut realms = std::collections::BTreeMap::new();
    realms.insert(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned(),
        strands,
    );
    realms
}

fn wrap_sidecar() -> (Vec<u8>, Value) {
    let sidecar = sample_sidecar();
    let json = serde_json::to_vec(&sidecar).unwrap();
    let kek = derive_vault_kek(ACCOUNT_SECRET.as_bytes()).unwrap();
    let body = build_mls_private_plaintext_backup_body_with_kek(
        SIDECAR_BACKUP_ID,
        ACTOR,
        DEVICE,
        &kek,
        &json,
    )
    .unwrap();
    (json, sign_wire_envelope(key_backup_wire(&body)))
}

#[test]
fn sidecar_backup_round_trips_under_account_secret() {
    let (json, body) = wrap_sidecar();
    let recovered = decrypt_mls_private_plaintext_backup(ACCOUNT_SECRET.as_bytes(), &body).unwrap();
    assert_eq!(recovered, json);
    // The decoded map equals the original sidecar.
    let map: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    > = serde_json::from_slice(&recovered).unwrap();
    assert_eq!(map, sample_sidecar());
}

#[test]
fn sidecar_backup_wrong_account_secret_fails() {
    let (_json, body) = wrap_sidecar();
    let result = decrypt_mls_private_plaintext_backup(b"a-different-account-secret", &body);
    assert!(result.is_err());
}

#[test]
fn sidecar_backup_has_expected_identifiers_and_no_plaintext_leak() {
    let (_json, body) = wrap_sidecar();
    assert!(is_mls_private_plaintext_backup(&body));
    assert_eq!(
        body["contents"][0]["item_kind"].as_str(),
        Some(MLS_PRIVATE_PLAINTEXT_ITEM_KIND.as_str())
    );
    assert_eq!(
        body["contents"][0]["secret_id"].as_str(),
        Some(MLS_PRIVATE_PLAINTEXT_SECRET_ID)
    );
    assert_eq!(body["backup_kind"], "secret_storage");
    assert_eq!(
        MLS_PRIVATE_PLAINTEXT_ITEM_KIND.as_str(),
        "mls_private_plaintext"
    );
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("author body"));
    assert!(!serialized.contains("author synthesis"));
}

#[test]
fn sidecar_backup_validates_as_secret_storage_envelope() {
    let (_json, body) = wrap_sidecar();
    validate_wire_envelope(&body, BackupKind::SecretStorage).expect(
        "mls_private_plaintext backup must validate as a secret_storage envelope (base64url-clean)",
    );
}

#[test]
fn select_sidecar_finds_and_prefers_highest_series_seq() {
    let (_json, base_body) = wrap_sidecar();
    let mut older = base_body.clone();
    older["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000a1");
    older["series_seq"] = serde_json::json!(1);
    let mut newer = base_body.clone();
    newer["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000a2");
    newer["series_seq"] = serde_json::json!(2);
    let payload = payload_with_inferred_active_series(vec![
        serde_json::json!({ "backup_id": "ak:backup:h", "backup_kind": "mls_history" }),
        older,
        newer.clone(),
    ]);
    let found = select_mls_private_plaintext_backup(&payload).expect("sidecar present");
    assert!(is_mls_private_plaintext_backup(&found));
    assert_eq!(found["backup_id"], newer["backup_id"]);
    // Absent payload -> None.
    assert!(select_mls_private_plaintext_backup(&serde_json::json!({ "backups": [] })).is_none());
}

#[test]
fn select_sidecar_honors_active_series_record() {
    let (_json, base_body) = wrap_sidecar();
    let mut active = base_body.clone();
    active["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000c1");
    active["series_id"] = serde_json::json!(ACTIVE_SECRET_STORAGE_SERIES);
    active["series_seq"] = serde_json::json!(0);
    active["created_at"] = serde_json::json!("2026-01-01T00:00:00.000Z");

    let mut stale = base_body;
    stale["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000c2");
    stale["series_id"] = serde_json::json!(STALE_SECRET_STORAGE_SERIES);
    stale["series_seq"] = serde_json::json!(99);
    stale["created_at"] = serde_json::json!("2026-12-31T23:59:59.000Z");

    let payload = serde_json::json!({
        "active_series": [
            active_series_record("secret_storage", ACTIVE_SECRET_STORAGE_SERIES)
        ],
        "backups": [stale, active.clone()]
    });

    let found = select_mls_private_plaintext_backup(&payload).expect("active sidecar present");
    assert_eq!(found["backup_id"], active["backup_id"]);
}
