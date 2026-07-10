use serde_json::Value;

use super::backup_body::{
    MLS_ACCOUNT_SECRET_ITEM_TYPE, MLS_ACCOUNT_SECRET_SECRET_ID, MLS_PRIVATE_PLAINTEXT_ITEM_TYPE,
    MLS_PRIVATE_PLAINTEXT_SECRET_ID, build_mls_account_secret_backup_body_with_kek,
    build_mls_account_secret_recovery_public_key_backup,
    build_mls_private_plaintext_backup_body_with_kek, decrypt_mls_account_secret_backup,
    decrypt_mls_private_plaintext_backup, is_mls_account_secret_backup,
    is_mls_private_plaintext_backup,
};
use super::restore::{
    mls_backup_prompt_required, mls_restore_prompt_required,
    restore_mls_history_with_passphrase_from_payload,
    restore_mls_history_with_recovery_key_from_payload,
};
use super::selection::{
    backup_series_seq, mls_account_secret_backup_version, mls_history_series_tail_ids,
    select_mls_account_secret_backup, select_mls_history_backups,
    select_mls_history_tail_for_realm, select_mls_private_plaintext_backup,
    select_preferred_mls_account_secret_backup,
};
use super::series::{apply_next_series, series_supersedes_digest, verify_series_chain};
use super::upload::select_superseded_backup_ids;
use crate::key_backup::{KeyBackupClass, validate_key_backup_envelope};
use crate::recovery_crypto::derive_vault_kek;
use crate::secure_key_store::MemorySecureKeyStore;

const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-00000000beef";
const ACTOR: &str = "did:web:alice.example";
const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
const PASSPHRASE: &[u8] = b"correct horse battery staple";
const ACCOUNT_SECRET: &str = "qr6h9rJ8nU0H2pP5w3sLx1A4bC7dE9fG2hI5jK8lM0N";
const ACTIVE_SECRET_STORAGE_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-0000000000a1";
const STALE_SECRET_STORAGE_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-0000000000a2";
const ACTIVE_MLS_HISTORY_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-0000000000b1";
const STALE_MLS_HISTORY_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-0000000000b2";

fn wrap() -> Value {
    let kek = derive_vault_kek(PASSPHRASE).unwrap();
    build_mls_account_secret_backup_body_with_kek(BACKUP_ID, ACTOR, DEVICE, &kek, ACCOUNT_SECRET)
        .unwrap()
}

/// Build the HPKE `recovery_public_key` account-secret backup that the
/// server-first recovery redesign treats as the preferred, passphrase-free
/// recovery material. The prompt gates (`mls_restore_prompt_required` /
/// `mls_backup_prompt_required`) key off this body, not the passphrase-wrapped
/// `wrap()` `secret_storage` body.
fn recovery_hpke_backup() -> Value {
    let (_sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    build_mls_account_secret_recovery_public_key_backup(
        "ak:backup:01964137-0000-7000-8000-00000000c0de",
        ACTOR,
        DEVICE,
        &pk,
        "did:web:alice.example#recovery",
        ACCOUNT_SECRET,
        1,
        None,
    )
    .unwrap()
}

fn active_series_record(backup_class: &str, active_series_id: &str) -> Value {
    serde_json::json!({
        "schema": crate::key_backup::KEY_BACKUP_ACTIVE_SERIES_SCHEMA,
        "actor_id": ACTOR,
        "backup_class": backup_class,
        "active_series_id": active_series_id,
        "previous_series_ids": [],
    })
}

// YOU-05-010: shared hermetic state-store fixture from `local_state`.
use crate::local_state::isolated_store_for_tests as temp_state_store;

fn history_envelope(
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    secret: &str,
) -> crate::mls::persistence::MlsSnapshotEnvelope {
    crate::mls::persistence::encrypt_state(
        realm_id,
        group_id,
        epoch,
        b"opaque sdk state bytes",
        secret,
        b"deterministic-salt",
    )
}

fn history_body(envelope: &crate::mls::persistence::MlsSnapshotEnvelope) -> Value {
    envelope.to_key_backup_body(
        "ak:backup:01964137-0000-7000-8000-00000000feed",
        ACTOR,
        DEVICE,
    )
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
        body["contents"][0]["item_type"].as_str(),
        Some(MLS_ACCOUNT_SECRET_ITEM_TYPE)
    );
    assert_eq!(
        body["contents"][0]["secret_id"].as_str(),
        Some(MLS_ACCOUNT_SECRET_SECRET_ID)
    );
    assert_eq!(body["backup_class"], "secret_storage");
    // item_type must be one both validators' allowlists accept.
    assert_eq!(MLS_ACCOUNT_SECRET_ITEM_TYPE, "mls_account_secret");
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
    validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage)).expect(
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
    // STANDARD base64 renders as `+`/`/`. Every one of these must still
    // validate (base64url-clean) and decrypt back to the input.
    for i in 0..32u32 {
        let secret = format!("account-secret-payload-with-entropy-{i:08x}-padding++//");
        let kek = derive_vault_kek(PASSPHRASE).unwrap();
        let body =
            build_mls_account_secret_backup_body_with_kek(BACKUP_ID, ACTOR, DEVICE, &kek, &secret)
                .unwrap();

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

        validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .unwrap_or_else(|err| panic!("iteration {i}: envelope must validate: {err}"));

        let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
        assert_eq!(recovered, secret.as_bytes(), "iteration {i}: round-trip");
    }
}

#[test]
fn select_account_secret_finds_it_in_a_list_payload() {
    let account_secret_body = wrap();
    // A `list_key_backups`-shaped payload mixing a history backup, an
    // unrelated recovery vault, and the account-secret backup.
    let payload = serde_json::json!({
        "backups": [
            { "backup_id": "ak:backup:a", "backup_class": "mls_history" },
            { "backup_id": "ak:backup:b", "backup_class": "recovery",
              "contents": [ { "secret_id": "inkson_recovery_vault_payload" } ] },
            account_secret_body.clone(),
        ]
    });
    let found = select_mls_account_secret_backup(&payload).expect("account secret present");
    assert!(is_mls_account_secret_backup(&found));
    // No-account-secret payload returns None.
    let none_payload = serde_json::json!({
        "backups": [ { "backup_id": "ak:backup:a", "backup_class": "mls_history" } ]
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
        None,
    )
    .unwrap();
    let payload = serde_json::json!({ "backups": [passphrase_wrapped.clone(), hpke.clone()] });

    let found = select_preferred_mls_account_secret_backup(&payload)
        .expect("preferred account secret present");
    assert_eq!(
        found["encryption"]["recipient_method"],
        serde_json::json!("recovery_public_key")
    );

    let passphrase_only = serde_json::json!({ "backups": [passphrase_wrapped.clone()] });
    assert!(select_preferred_mls_account_secret_backup(&passphrase_only).is_none());
}

#[test]
fn select_account_secret_prefers_highest_series_seq() {
    let mut older = wrap();
    older["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-00000000bee1");
    older["series_seq"] = serde_json::json!(1);
    let mut newer = wrap();
    newer["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-00000000bee2");
    newer["series_seq"] = serde_json::json!(2);
    let payload = serde_json::json!({
        "backups": [newer.clone(), older]
    });

    let found = select_mls_account_secret_backup(&payload).expect("account secret present");

    assert_eq!(found["backup_id"], newer["backup_id"]);
}

#[test]
fn prompt_required_when_local_secret_exists_but_history_is_missing() {
    let store = MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&store, ACTOR, "stale-local-secret").unwrap();
    let state = temp_state_store("prompt-missing-history");
    let envelope = history_envelope("ak:realm:prompt", "group-a", 7, ACCOUNT_SECRET);
    let payload = serde_json::json!({
        "backups": [recovery_hpke_backup(), history_body(&envelope)]
    });

    assert!(mls_restore_prompt_required(
        &payload, &state, &store, ACTOR, DEVICE
    ));
}

#[test]
fn prompt_not_required_when_local_history_is_current_and_decryptable() {
    let store = MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
    let mut state = temp_state_store("prompt-current-history");
    let envelope = history_envelope("ak:realm:prompt", "group-a", 7, ACCOUNT_SECRET);
    state.save_mls_snapshot(envelope.realm_id.clone(), envelope.clone());
    let payload = serde_json::json!({
        "backups": [wrap(), history_body(&envelope)]
    });

    assert!(!mls_restore_prompt_required(
        &payload, &state, &store, ACTOR, DEVICE
    ));
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
    forged_tail["supersedes"] = serde_json::json!("ak:backup:does-not-exist");
    forged_tail["supersedes_digest"] = serde_json::json!("sha256:deadbeef");

    let err = verify_series_chain(&forged_tail, &[genesis, forged_tail.clone()])
        .expect_err("a chain missing series_seq 1 must be rejected");
    assert!(err.to_string().contains("series_chain_broken"));
}

#[test]
fn verify_series_chain_accepts_well_formed_successor() {
    // Mirror what the upload path now produces: genesis then a successor
    // linked by apply_next_series.
    let mut genesis = wrap();
    genesis["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000d0");
    genesis["series_id"] =
        serde_json::json!("ak:backup_series:01964137-0000-7000-8000-0000000000d1");
    genesis["series_seq"] = serde_json::json!(0);

    let mut successor = wrap();
    successor["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000d2");
    apply_next_series(Some(&genesis), &mut successor)
        .expect("successor series metadata must build");

    verify_series_chain(&successor, &[genesis, successor.clone()])
        .expect("an apply_next_series-linked successor must verify");
}

#[test]
fn prompt_required_when_local_snapshot_uses_forked_random_secret() {
    // P0 regression: a new device's Welcome bootstrap minted a random
    // account secret and saved a self-consistent local snapshot under it,
    // while the server holds history encrypted under the REAL account
    // secret. The old detection only checked the (self-decryptable) local
    // snapshot and silently skipped the restore prompt, forking the chain.
    let store = MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&store, ACTOR, "forked-random-secret").unwrap();
    let mut state = temp_state_store("prompt-forked-secret");
    // Server backup is encrypted under the real account secret...
    let server_envelope = history_envelope("ak:realm:prompt", "group-a", 7, ACCOUNT_SECRET);
    // ...but the local snapshot was saved under the forked random secret at
    // the same (or higher) epoch, so it self-decrypts and passes the old
    // epoch/group gates.
    let local_envelope = history_envelope("ak:realm:prompt", "group-a", 7, "forked-random-secret");
    state.save_mls_snapshot(local_envelope.realm_id.clone(), local_envelope);
    let payload = serde_json::json!({
        "backups": [recovery_hpke_backup(), history_body(&server_envelope)]
    });

    assert!(
        mls_restore_prompt_required(&payload, &state, &store, ACTOR, DEVICE),
        "forked random local secret must still trigger the restore prompt"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn fresh_device_restores_via_recovery_key_no_passphrase() {
    // A3 / the user's "cleared storage = device B" point: a brand-new device
    // (empty secure store) recovers WITHOUT the passphrase, using only the
    // recovery PRIVATE key to HPKE-open the account secret. Fully end-to-end
    // on host (real OpenMLS group), no live soland.
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    let device_a = "ak:device:01964137-0000-7000-8000-00000000000a";
    let realm = "ak:realm:01964137-0000-7000-8000-0000000000ab";
    let identity = ArkretMlsIdentity::new_basic(
        Did::new(ACTOR.to_owned()).unwrap(),
        DeviceId::new(device_a.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    let record = group.export_state_record().unwrap();
    // Device A's history is encrypted under the account secret.
    let history = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        ACCOUNT_SECRET,
        b"deterministic-salt",
    );

    // The account secret is ALSO backed up HPKE-sealed to the recovery
    // public key (the passphrase-free path). Only the recovery PRIVATE key
    // opens it.
    let (recovery_sk, recovery_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    let account_secret_body = build_mls_account_secret_recovery_public_key_backup(
        BACKUP_ID,
        ACTOR,
        DEVICE,
        &recovery_pk,
        "did:web:alice.example#recovery",
        ACCOUNT_SECRET,
        crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION,
        None,
    )
    .unwrap();

    let payload = serde_json::json!({
        "backups": [account_secret_body, history_body(&history)]
    });
    // Device B: empty secure store, empty state store.
    let store = MemorySecureKeyStore::new();
    let mut state = temp_state_store("fresh-device-recovery-key");

    let report = restore_mls_history_with_recovery_key_from_payload(
        &payload,
        &mut state,
        &store,
        ACTOR,
        DEVICE,
        &recovery_sk,
        None,
    )
    .unwrap();

    assert!(
        report.account_secret_imported,
        "account secret HPKE-imported"
    );
    assert_eq!(report.restored, 1, "history restored");
    assert_eq!(report.failed, 0);
    let loaded = crate::mls::runtime::load_account_mls_secret(&store, ACTOR)
        .unwrap()
        .expect("account secret now local");
    assert_eq!(loaded.secret, ACCOUNT_SECRET);
    assert!(
        state.mls_snapshot_for(realm).is_some(),
        "snapshot decryptable"
    );

    // A WRONG recovery key cannot recover.
    let (other_sk, _other_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
    let store2 = MemorySecureKeyStore::new();
    let mut state2 = temp_state_store("fresh-device-wrong-key");
    assert!(
        restore_mls_history_with_recovery_key_from_payload(
            &payload,
            &mut state2,
            &store2,
            ACTOR,
            DEVICE,
            &other_sk,
            None,
        )
        .is_err(),
        "wrong recovery key must fail"
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
        Some(("ak:recovery_policy:P1", 3)),
    )
    .unwrap();

    // Matching policy → opens.
    let (secret, _version) = open_mls_account_secret_recovery_public_key_backup(
        &recovery_sk,
        &body,
        Some(("ak:recovery_policy:P1", 3)),
    )
    .unwrap();
    assert_eq!(secret, ACCOUNT_SECRET);

    // Stale policy version → rejected before import.
    assert!(
        open_mls_account_secret_recovery_public_key_backup(
            &recovery_sk,
            &body,
            Some(("ak:recovery_policy:P1", 2)),
        )
        .is_err(),
        "old policy version must be rejected"
    );

    // Different policy id → rejected.
    assert!(
        open_mls_account_secret_recovery_public_key_backup(
            &recovery_sk,
            &body,
            Some(("ak:recovery_policy:P2", 3)),
        )
        .is_err(),
        "different policy id must be rejected"
    );

    // No expected policy supplied → check skipped (legacy / offline path).
    assert!(open_mls_account_secret_recovery_public_key_backup(&recovery_sk, &body, None).is_ok());
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
        None,
    )
    .unwrap();
    // SEC-05: with an expected policy and no ref on the envelope → fail closed.
    assert!(
        open_mls_account_secret_recovery_public_key_backup(
            &recovery_sk,
            &body,
            Some(("ak:recovery_policy:P1", 3)),
        )
        .is_err(),
        "missing recovery_policy_ref must fail closed when a policy is expected"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn restore_replaces_stale_local_secret_before_history_replay() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    let device_a = "ak:device:01964137-0000-7000-8000-00000000000a";
    let realm = "ak:realm:01964137-0000-7000-8000-0000000000ab";
    let identity = ArkretMlsIdentity::new_basic(
        Did::new(ACTOR.to_owned()).unwrap(),
        DeviceId::new(device_a.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    let record = group.export_state_record().unwrap();
    let envelope = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        ACCOUNT_SECRET,
        b"deterministic-salt",
    );
    let payload = serde_json::json!({
        "backups": [wrap(), history_body(&envelope)]
    });
    let store = MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret_version(
        &store,
        ACTOR,
        crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION + 1,
        "stale-local-secret",
    )
    .unwrap();
    let mut state = temp_state_store("restore-stale-secret");

    let report = restore_mls_history_with_passphrase_from_payload(
        &payload, &mut state, &store, ACTOR, DEVICE, PASSPHRASE,
    )
    .unwrap();

    assert!(report.account_secret_imported);
    assert_eq!(report.restored, 1);
    assert_eq!(report.failed, 0);
    let loaded = crate::mls::runtime::load_account_mls_secret(&store, ACTOR)
        .unwrap()
        .expect("secret present");
    assert_eq!(
        loaded.version,
        crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION
    );
    assert_eq!(loaded.secret, ACCOUNT_SECRET);
    assert!(state.mls_snapshot_for(realm).is_some());
}

#[test]
fn backup_prompt_not_required_when_no_local_secret() {
    // User never used encryption: no local account secret, server has no
    // backup either. Don't nag.
    let store = MemorySecureKeyStore::new();
    let payload = serde_json::json!({ "backups": [] });
    assert!(!mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
}

#[test]
fn backup_prompt_required_when_local_secret_and_no_server_backup() {
    // User has used encryption (local secret present) but never backed it
    // up to the server -> prompt them to set a recovery passphrase.
    let store = MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
    let payload = serde_json::json!({
        "backups": [ { "backup_id": "ak:backup:a", "backup_class": "mls_history" } ]
    });
    assert!(mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
}

#[test]
fn backup_prompt_not_required_when_server_backup_present() {
    // Server already holds the passphrase-free recovery-public-key account-secret
    // backup: fresh-device recovery material exists, so nothing to upload.
    let store = MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
    let payload = serde_json::json!({ "backups": [recovery_hpke_backup()] });
    assert!(!mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
}

#[test]
fn select_superseded_picks_all_old_account_and_history() {
    // Phase 4: after rotation, delete EVERY old account-secret + EVERY old
    // history backup (not just rewrapped Realms) — leaving any behind would
    // orphan it under the deleted old secret while keeping it readable by the
    // compromised old secret. Only the freshly-uploaded `keep` ids survive.
    let mut old_account = wrap();
    old_account["backup_id"] = serde_json::json!("ak:backup:old-account");
    let env_a = history_envelope("ak:realm:a", "g-a", 1, ACCOUNT_SECRET);
    let mut hist_a = history_body(&env_a);
    hist_a["backup_id"] = serde_json::json!("ak:backup:old-hist-a");
    // A server-only realm (not rewrapped locally) — MUST still be deleted.
    let env_b = history_envelope("ak:realm:b", "g-b", 1, ACCOUNT_SECRET);
    let mut hist_b = history_body(&env_b);
    hist_b["backup_id"] = serde_json::json!("ak:backup:old-hist-b");
    // The just-uploaded new history for realm a (in keep) must NOT be deleted.
    let mut new_hist_a = history_body(&env_a);
    new_hist_a["backup_id"] = serde_json::json!("ak:backup:new-hist-a");
    let payload = serde_json::json!({ "backups": [old_account, hist_a, hist_b, new_hist_a] });

    let keep = vec![
        "ak:backup:new-account".to_owned(),
        "ak:backup:new-hist-a".to_owned(),
    ];
    let superseded = select_superseded_backup_ids(&payload, &keep);
    assert!(superseded.contains(&"ak:backup:old-account".to_owned()));
    assert!(superseded.contains(&"ak:backup:old-hist-a".to_owned()));
    assert!(
        superseded.contains(&"ak:backup:old-hist-b".to_owned()),
        "server-only (non-rewrapped) old history must ALSO be deleted"
    );
    assert!(
        !superseded.contains(&"ak:backup:new-hist-a".to_owned()),
        "freshly uploaded history must be kept"
    );
}

#[test]
fn select_superseded_orders_chain_links_tail_first() {
    // soland rejects deleting a non-tail chain link
    // (`active_series_non_tail_delete_forbidden`), so the rotation cleanup
    // must unwind each superseded series from the tail down.
    let series = "ak:backup_series:01964137-0000-7000-8000-0000000000d0";
    let env = history_envelope("ak:realm:a", "g-a", 1, ACCOUNT_SECRET);
    let mut link0 = history_body(&env);
    link0["backup_id"] = serde_json::json!("ak:backup:link0");
    link0["series_id"] = serde_json::json!(series);
    link0["series_seq"] = serde_json::json!(0);
    let mut link1 = history_body(&env);
    link1["backup_id"] = serde_json::json!("ak:backup:link1");
    link1["series_id"] = serde_json::json!(series);
    link1["series_seq"] = serde_json::json!(1);
    let mut link2 = history_body(&env);
    link2["backup_id"] = serde_json::json!("ak:backup:link2");
    link2["series_id"] = serde_json::json!(series);
    link2["series_seq"] = serde_json::json!(2);
    // List order is deliberately shuffled.
    let payload = serde_json::json!({ "backups": [link1, link2, link0] });

    let superseded = select_superseded_backup_ids(&payload, &[]);
    assert_eq!(
        superseded,
        vec![
            "ak:backup:link2".to_owned(),
            "ak:backup:link1".to_owned(),
            "ak:backup:link0".to_owned(),
        ],
        "within a series, deletes must run tail-first (descending series_seq)"
    );
}

#[test]
fn mls_history_successor_chains_onto_previous_tail() {
    // §7.10 continuous backup: the n+1-th upload for a Realm must extend
    // the SAME series (inherited series_id, seq+1, supersedes +
    // supersedes_digest over the canonical predecessor) instead of opening
    // a parallel genesis series.
    let env_v1 = history_envelope("ak:realm:a", "g-a", 1, ACCOUNT_SECRET);
    let genesis = history_body(&env_v1);
    // Genesis shape: fresh series, seq 0, no predecessor fields.
    assert_eq!(genesis["series_seq"], 0);
    assert!(genesis.get("supersedes").is_none());
    assert!(genesis.get("supersedes_digest").is_none());

    let env_v2 = history_envelope("ak:realm:a", "g-a", 2, ACCOUNT_SECRET);
    let mut successor = env_v2.to_key_backup_body(
        "ak:backup:01964137-0000-7000-8000-000000000123",
        ACTOR,
        DEVICE,
    );
    apply_next_series(Some(&genesis), &mut successor).unwrap();

    assert_eq!(successor["series_id"], genesis["series_id"]);
    assert_eq!(successor["series_seq"], 1);
    assert_eq!(successor["supersedes"], genesis["backup_id"]);
    assert_eq!(
        successor["supersedes_digest"].as_str().unwrap(),
        series_supersedes_digest(&genesis).unwrap(),
        "supersedes_digest must be the canonical sha256 of the predecessor \
         envelope without auth_data.signature (soland recomputes and 409s \
         on mismatch)"
    );
    // Still a valid mls_history envelope after the successor mutation.
    validate_key_backup_envelope(&successor, Some(KeyBackupClass::MlsHistory)).unwrap();
}

#[test]
fn mls_history_tail_selection_is_per_realm_and_per_series() {
    let series_a = "ak:backup_series:01964137-0000-7000-8000-0000000000a0";
    let env_a = history_envelope("ak:realm:a", "g-a", 1, ACCOUNT_SECRET);
    let mut a0 = history_body(&env_a);
    a0["backup_id"] = serde_json::json!("ak:backup:a0");
    a0["series_id"] = serde_json::json!(series_a);
    a0["series_seq"] = serde_json::json!(0);
    let env_a2 = history_envelope("ak:realm:a", "g-a", 2, ACCOUNT_SECRET);
    let mut a1 = history_body(&env_a2);
    a1["backup_id"] = serde_json::json!("ak:backup:a1");
    a1["series_id"] = serde_json::json!(series_a);
    a1["series_seq"] = serde_json::json!(1);
    let env_b = history_envelope("ak:realm:b", "g-b", 5, ACCOUNT_SECRET);
    let mut b0 = history_body(&env_b);
    b0["backup_id"] = serde_json::json!("ak:backup:b0");
    // Non-history classes must never be selected as history tails.
    let account = wrap();
    let payload = serde_json::json!({ "backups": [a0, a1.clone(), b0.clone(), account] });

    // Per-Realm chaining target: realm a -> highest-seq link a1; realm b
    // -> its genesis; unknown realm -> none.
    let tail_a = select_mls_history_tail_for_realm(&payload, "ak:realm:a").unwrap();
    assert_eq!(tail_a["backup_id"], "ak:backup:a1");
    let tail_b = select_mls_history_tail_for_realm(&payload, "ak:realm:b").unwrap();
    assert_eq!(tail_b["backup_id"], "ak:backup:b0");
    assert!(select_mls_history_tail_for_realm(&payload, "ak:realm:absent").is_none());

    // Restore-side quota guard: only series tails survive the filter.
    let tails = mls_history_series_tail_ids(&payload);
    assert!(tails.contains("ak:backup:a1"));
    assert!(tails.contains("ak:backup:b0"));
    assert!(
        !tails.contains("ak:backup:a0"),
        "superseded chain links must not be fetched/restored"
    );
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
    tail["created_at"] = serde_json::json!("2026-01-01T00:00:00Z");
    // A resurrected old seq=1 with a LATER timestamp (server injection).
    let mut stale = wrap();
    stale["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000e1");
    stale["series_id"] = serde_json::json!(series);
    stale["series_seq"] = serde_json::json!(1);
    stale["created_at"] = serde_json::json!("2026-12-31T23:59:59Z");

    let payload = serde_json::json!({ "backups": [stale, tail.clone()] });
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
    active["created_at"] = serde_json::json!("2026-01-01T00:00:00Z");
    active["contents"][0]["secret_version"] = serde_json::json!(1);

    let mut stale = wrap();
    stale["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000a2");
    stale["series_id"] = serde_json::json!(STALE_SECRET_STORAGE_SERIES);
    stale["series_seq"] = serde_json::json!(99);
    stale["created_at"] = serde_json::json!("2026-12-31T23:59:59Z");
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
fn select_history_honors_active_series_record() {
    let env_a1 = history_envelope("ak:realm:a", "g-a", 1, ACCOUNT_SECRET);
    let mut active0 = history_body(&env_a1);
    active0["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000b0");
    active0["series_id"] = serde_json::json!(ACTIVE_MLS_HISTORY_SERIES);
    active0["series_seq"] = serde_json::json!(0);
    active0["created_at"] = serde_json::json!("2026-01-01T00:00:00Z");

    let env_a2 = history_envelope("ak:realm:a", "g-a", 2, ACCOUNT_SECRET);
    let mut active1 = history_body(&env_a2);
    active1["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000b1");
    active1["series_id"] = serde_json::json!(ACTIVE_MLS_HISTORY_SERIES);
    active1["series_seq"] = serde_json::json!(1);
    active1["created_at"] = serde_json::json!("2026-01-02T00:00:00Z");

    let env_stale = history_envelope("ak:realm:a", "g-a", 99, ACCOUNT_SECRET);
    let mut stale = history_body(&env_stale);
    stale["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000b2");
    stale["series_id"] = serde_json::json!(STALE_MLS_HISTORY_SERIES);
    stale["series_seq"] = serde_json::json!(99);
    stale["created_at"] = serde_json::json!("2026-12-31T23:59:59Z");

    let payload = serde_json::json!({
        "active_series": [
            active_series_record("mls_history", ACTIVE_MLS_HISTORY_SERIES)
        ],
        "backups": [stale, active0.clone(), active1.clone()]
    });

    let histories = select_mls_history_backups(&payload);
    assert_eq!(histories.len(), 2);
    assert!(histories.iter().all(|body| {
        body.get("series_id").and_then(Value::as_str) == Some(ACTIVE_MLS_HISTORY_SERIES)
    }));

    let tails = mls_history_series_tail_ids(&payload);
    assert!(tails.contains("ak:backup:01964137-0000-7000-8000-0000000000b1"));
    assert!(!tails.contains("ak:backup:01964137-0000-7000-8000-0000000000b0"));
    assert!(!tails.contains("ak:backup:01964137-0000-7000-8000-0000000000b2"));

    let tail = select_mls_history_tail_for_realm(&payload, "ak:realm:a").unwrap();
    assert_eq!(tail["backup_id"], active1["backup_id"]);
}

#[test]
fn select_history_backups_filters_by_class() {
    let payload = serde_json::json!({
        "backups": [
            { "backup_id": "ak:backup:a", "backup_class": "mls_history" },
            { "backup_id": "ak:backup:b", "backup_class": "secret_storage" },
            { "backup_id": "ak:backup:c", "backup_class": "mls_history" },
            { "backup_id": "ak:backup:d" },
        ]
    });
    let histories = select_mls_history_backups(&payload);
    assert_eq!(histories.len(), 2);
    assert!(
        histories
            .iter()
            .all(|b| { b.get("backup_class").and_then(Value::as_str) == Some("mls_history") })
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
    strands.insert("ak:strand:alpha".to_owned(), fields);
    let mut realms = std::collections::BTreeMap::new();
    realms.insert("ak:realm:demo".to_owned(), strands);
    realms
}

fn wrap_sidecar() -> (Vec<u8>, Value) {
    let sidecar = sample_sidecar();
    let json = serde_json::to_vec(&sidecar).unwrap();
    let kek = derive_vault_kek(ACCOUNT_SECRET.as_bytes()).unwrap();
    let body =
        build_mls_private_plaintext_backup_body_with_kek(BACKUP_ID, ACTOR, DEVICE, &kek, &json)
            .unwrap();
    (json, body)
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
        body["contents"][0]["item_type"].as_str(),
        Some(MLS_PRIVATE_PLAINTEXT_ITEM_TYPE)
    );
    assert_eq!(
        body["contents"][0]["secret_id"].as_str(),
        Some(MLS_PRIVATE_PLAINTEXT_SECRET_ID)
    );
    assert_eq!(body["backup_class"], "secret_storage");
    assert_eq!(MLS_PRIVATE_PLAINTEXT_ITEM_TYPE, "mls_private_plaintext");
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("author body"));
    assert!(!serialized.contains("author synthesis"));
}

#[test]
fn sidecar_backup_validates_as_secret_storage_envelope() {
    let (_json, body) = wrap_sidecar();
    validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage)).expect(
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
    let payload = serde_json::json!({
        "backups": [
            { "backup_id": "ak:backup:h", "backup_class": "mls_history" },
            older,
            newer.clone(),
        ]
    });
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
    active["created_at"] = serde_json::json!("2026-01-01T00:00:00Z");

    let mut stale = base_body;
    stale["backup_id"] = serde_json::json!("ak:backup:01964137-0000-7000-8000-0000000000c2");
    stale["series_id"] = serde_json::json!(STALE_SECRET_STORAGE_SERIES);
    stale["series_seq"] = serde_json::json!(99);
    stale["created_at"] = serde_json::json!("2026-12-31T23:59:59Z");

    let payload = serde_json::json!({
        "active_series": [
            active_series_record("secret_storage", ACTIVE_SECRET_STORAGE_SERIES)
        ],
        "backups": [stale, active.clone()]
    });

    let found = select_mls_private_plaintext_backup(&payload).expect("active sidecar present");
    assert_eq!(found["backup_id"], active["backup_id"]);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn restore_brings_back_the_sidecar_into_the_store() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    // Build a real, decryptable account-secret + history backup so Step 1/2
    // succeed and the account secret is local for the sidecar KEK source.
    let device_a = "ak:device:01964137-0000-7000-8000-00000000000a";
    let realm = "ak:realm:01964137-0000-7000-8000-0000000000ab";
    let identity = ArkretMlsIdentity::new_basic(
        Did::new(ACTOR.to_owned()).unwrap(),
        DeviceId::new(device_a.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    let record = group.export_state_record().unwrap();
    let history = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        ACCOUNT_SECRET,
        b"deterministic-salt",
    );

    // The sidecar is encrypted under the ACCOUNT SECRET (not the passphrase).
    let (_json, sidecar_body) = wrap_sidecar();

    let payload = serde_json::json!({
        "backups": [wrap(), history_body(&history), sidecar_body]
    });
    let store = MemorySecureKeyStore::new();
    let mut state = temp_state_store("restore-sidecar");

    let report = restore_mls_history_with_passphrase_from_payload(
        &payload, &mut state, &store, ACTOR, DEVICE, PASSPHRASE,
    )
    .unwrap();

    assert!(report.account_secret_imported);
    assert_eq!(report.restored, 1);
    assert!(
        report.private_plaintext_restored,
        "sidecar must be restored"
    );
    assert_eq!(
        state.private_plaintext_for("ak:realm:demo", "ak:strand:alpha", "body"),
        Some("\"author body\"".to_owned())
    );
    assert_eq!(
        state.private_plaintext_for("ak:realm:demo", "ak:strand:alpha", "synthesis"),
        Some("\"author synthesis\"".to_owned())
    );
}
