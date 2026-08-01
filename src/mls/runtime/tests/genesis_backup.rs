//! Tests for `ak.mls.genesis` payload construction and MLS-history backup
//! encode / decode / restore.

use serde_json::json;

use crate::mls::runtime::*;
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStoreError};
use crate::state::isolated_store_for_tests as temp_state_store;

fn genesis_governance_binding(group_id: &str) -> arkret_sdk::MlsGovernanceBindingPayload {
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let frontier =
        vec![arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-0000000000aa").unwrap()];
    let policy_root = arkret_sdk::Hash::new(
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    let capability_root = policy_root.clone();
    let discussion_metadata_digest = policy_root.clone();
    // Genesis installs epoch 0 (governance binding epoch 0 -> 0).
    arkret_sdk::MlsGovernanceBindingPayload::realm(
        realm_id,
        group_id,
        0,
        0,
        frontier,
        vec![arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap()],
        policy_root,
        capability_root,
        discussion_metadata_digest,
        arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        arkret_sdk::CORE_REDUCER_PROFILE,
    )
    .unwrap()
}

#[test]
fn build_mls_genesis_payload_has_required_fields() {
    let mut state = temp_state_store("genesis-payload");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";

    super::seed_genesis_governance_proof(&mut state, realm);
    let summary = ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot should be created");
    let binding = genesis_governance_binding(&summary.group_id);
    let payload = build_mls_genesis_payload(&summary, actor, device, &binding).unwrap();

    // epoch MUST be the literal 0 the schema/reducer require.
    assert_eq!(payload["epoch"].as_u64(), Some(0));
    assert_eq!(payload["creator_principal_id"].as_str(), Some(actor));
    assert_eq!(payload["creator_device_id"].as_str(), Some(device));
    assert_eq!(
        payload["mls_group_id"].as_str(),
        Some(summary.group_id.as_str())
    );
    // cipher_suite is the SDK ciphersuite string form — non-empty.
    assert!(!payload["cipher_suite"].as_str().unwrap_or("").is_empty());
    // governance_binding present and carries the genesis 0 -> 0 epochs.
    assert!(payload.get("governance_binding").is_some());
    assert_eq!(
        payload["governance_binding"]["previous_epoch"].as_u64(),
        Some(0)
    );
    assert_eq!(
        payload["governance_binding"]["next_epoch"].as_u64(),
        Some(0)
    );
    // effective_scope mirrors the governance binding's.
    assert_eq!(
        payload["effective_scope"],
        payload["governance_binding"]["effective_scope"]
    );
    // group_info / ratchet_tree digest fields present and sha256-shaped.
    let group_info_digest = payload["group_info_digest"].as_str().unwrap();
    let ratchet_tree_digest = payload["ratchet_tree_digest"].as_str().unwrap();
    assert!(group_info_digest.starts_with("sha256:"));
    assert!(ratchet_tree_digest.starts_with("sha256:"));
    assert_eq!(group_info_digest, summary.schedule_hash);
    // created_at present.
    assert!(payload["created_at"].as_str().unwrap_or("").contains('T'));

    // Validate against the registered canonical `mls_genesis_payload`
    // schema so the full payload passes strict client/server validation.
    let catalog = arkret_sdk::schema::event_payload_validator_catalog().unwrap();
    if catalog
        .missing_payload_validators_for(std::iter::once("ak.mls.genesis"))
        .is_empty()
    {
        catalog
            .validate_payload("ak.mls.genesis", &payload)
            .expect("genesis payload must satisfy the registered schema");
    }
}

#[test]
fn existing_epoch_zero_snapshot_restores_genesis_summary() {
    let mut state = temp_state_store("genesis-summary-restore");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";

    super::seed_genesis_governance_proof(&mut state, realm);
    let fresh = ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot should be created");
    let restored =
        initial_mls_snapshot_summary_from_existing(&state, &secure, realm, actor, device)
            .unwrap()
            .expect("epoch-0 snapshot restores summary");

    assert_eq!(restored.realm_id, fresh.realm_id);
    assert_eq!(restored.group_id, fresh.group_id);
    assert_eq!(restored.epoch, 0);
    assert_eq!(restored.schedule_hash, fresh.schedule_hash);
    assert_eq!(restored.ratchet_tree, fresh.ratchet_tree);
}

#[test]
fn legacy_epoch_zero_snapshot_without_governance_binding_fails_closed() {
    let mut state = temp_state_store("legacy-genesis-summary");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let secret = load_or_create_device_snapshot_secret(&secure, actor, device).unwrap();
    let identity = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new(actor.to_owned()).unwrap(),
        arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    assert!(group.current_governance_binding().unwrap().is_none());
    let record = group.export_state_record().unwrap();
    let bytes = serde_json::to_vec(&record).unwrap();
    let snapshot = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &bytes,
        &secret,
        b"legacy-genesis-salt",
    );
    state.save_mls_snapshot(realm, snapshot);
    super::seed_genesis_governance_proof(&mut state, realm);

    let error = initial_mls_snapshot_summary_from_existing(&state, &secure, realm, actor, device)
        .unwrap_err();

    assert!(error.user_message().contains("recreate local MLS state"));
}

#[test]
fn mls_genesis_emitted_flag_is_idempotent() {
    let mut state = temp_state_store("genesis-idempotent");
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    assert!(!state.mls_genesis_emitted_for(realm));
    state.mark_mls_genesis_emitted(realm);
    assert!(state.mls_genesis_emitted_for(realm));
    // Re-marking is a no-op / stays true.
    state.mark_mls_genesis_emitted(realm);
    assert!(state.mls_genesis_emitted_for(realm));
}

#[test]
fn pending_genesis_event_round_trips_exactly_and_clears_on_accept() {
    let mut state = temp_state_store("pending-genesis-event");
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let actor = "did:web:alice.example";
    let group_id = arkret_sdk::base64url_encode(realm.as_bytes());
    let binding = genesis_governance_binding(&group_id);
    let summary = InitialMlsSnapshotSummary {
        realm_id: realm.to_owned(),
        group_id: group_id.clone(),
        epoch: 0,
        ratchet_tree: "cmF0Y2hldC10cmVl".to_owned(),
        schedule_hash: format!("sha256:{}", "4".repeat(64)),
        cipher_suite: arkret_sdk::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.to_owned(),
    };
    let payload = build_mls_genesis_payload(
        &summary,
        actor,
        "ak:device:01904100-0000-7000-8000-000000000001",
        &binding,
    )
    .unwrap();
    let event =
        crate::operation::ak_ops::mls_genesis_with_governance(realm, actor, &group_id, &payload)
            .build_sdk_event("inkson")
            .unwrap();

    state
        .save_pending_mls_genesis_event_for_effective_scope(realm, None, event.clone())
        .unwrap();
    assert_eq!(
        state.pending_mls_genesis_event_for_effective_scope(realm, None),
        Some(event.clone())
    );

    state.mark_mls_genesis_emitted_for_effective_scope_with_event(realm, None, &event.event_id);
    assert!(
        state
            .pending_mls_genesis_event_for_effective_scope(realm, None)
            .is_none()
    );
}

#[test]
fn mls_history_backup_body_decodes_to_snapshot_envelope() {
    let envelope = crate::mls::persistence::encrypt_state(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        "group-a",
        8,
        b"opaque sdk state",
        "device-secret",
        b"deterministic-salt",
    );
    let body = envelope
        .to_key_backup_body(
            "ak:backup:01904100-0000-7000-8000-000000000002",
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
            &derive_mls_history_backup_key("device-secret").unwrap(),
            None,
        )
        .unwrap();

    let decoded = decode_mls_history_backup_envelope(&body, "device-secret").unwrap();

    assert_eq!(decoded.realm_id, envelope.realm_id);
    assert_eq!(decoded.group_id, envelope.group_id);
    assert_eq!(decoded.epoch, envelope.epoch);
    assert_eq!(body["backup_kind"], "mls_history");
    assert_eq!(body["encryption"]["recipient_method"], "secret_storage_key");
    assert!(body["encryption"].get("kdf").is_none());
    assert!(body.get("plaintext").is_none());
    assert!(body.get("serialized_state").is_none());
}

#[test]
fn mls_history_backup_decode_rejects_metadata_mismatch() {
    let envelope = crate::mls::persistence::encrypt_state(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        "group-a",
        8,
        b"opaque sdk state",
        "device-secret",
        b"deterministic-salt",
    );
    let mut body = envelope
        .to_key_backup_body(
            "ak:backup:01904100-0000-7000-8000-000000000002",
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
            &derive_mls_history_backup_key("device-secret").unwrap(),
            None,
        )
        .unwrap();
    body["contents"][0]["epoch"] = json!(7);

    let error = decode_mls_history_backup_envelope(&body, "device-secret").unwrap_err();

    assert!(matches!(error, MlsRuntimeError::BackupDecode(_)));
    assert!(error.user_message().contains("epoch mismatch"));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn restore_mls_history_backup_saves_snapshot_when_fresh() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000004";
    let store = MemorySecureKeyStore::new();
    let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
    let identity = ArkretMlsIdentity::new_basic(
        Did::new(actor.to_owned()).unwrap(),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    let record = group.export_state_record().unwrap();
    let group_state_event_id =
        arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-0000000000aa").unwrap();
    let mut envelope = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        &secret,
        b"deterministic-salt",
    );
    envelope.group_state_event_id = Some(group_state_event_id.clone());
    let body = envelope
        .to_key_backup_body(
            "ak:backup:01904100-0000-7000-8000-000000000002",
            actor,
            device,
            &derive_mls_history_backup_key(&secret).unwrap(),
            None,
        )
        .unwrap();
    let mut state = temp_state_store("restore-fresh");

    let restored =
        restore_mls_history_backup_with_device_snapshot(&mut state, &store, actor, device, &body)
            .unwrap();

    assert_eq!(restored.realm_id, realm);
    assert_eq!(restored.envelope_epoch, record.epoch);
    assert_eq!(restored.epoch_floor, 0);
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, record.epoch);
    assert_eq!(
        body.pointer("/contents/0/last_event_id")
            .and_then(serde_json::Value::as_str),
        Some(group_state_event_id.as_str())
    );
    assert_eq!(
        state
            .mls_group_state_ref_for_effective_scope(realm, None, &record.group_id, record.epoch,)
            .unwrap(),
        group_state_event_id
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn restore_mls_history_backup_rejects_epoch_rollback() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000002";
    let store = MemorySecureKeyStore::new();
    let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
    let identity = ArkretMlsIdentity::new_basic(
        Did::new(actor.to_owned()).unwrap(),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    let record = group.export_state_record().unwrap();
    let envelope = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        &secret,
        b"deterministic-salt",
    );
    let body = envelope
        .to_key_backup_body(
            "ak:backup:01904100-0000-7000-8000-000000000002",
            actor,
            device,
            &derive_mls_history_backup_key(&secret).unwrap(),
            None,
        )
        .unwrap();
    let mut state = temp_state_store("restore-rollback");
    state.set_realm_seal_view(
        realm,
        crate::state::LocalSealView {
            mls_epoch: Some(record.epoch + 1),
            ..Default::default()
        },
    );

    let error =
        restore_mls_history_backup_with_device_snapshot(&mut state, &store, actor, device, &body)
            .unwrap_err();

    assert!(error.user_message().contains("outdated snapshot"));
    assert!(state.mls_snapshot_for(realm).is_none());
}

/// End-to-end regression guard for "same account, brand-new browser sees
/// history" (Option A). Proves cross-device MLS-history recovery works using
/// ONLY the account-secret backup unwrapped with the recovery passphrase —
/// device B has NO local random secret of its own.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn cross_device_recovery_restores_history_without_local_secret() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    use crate::mls::account_recovery::{
        build_mls_account_secret_backup_body_with_kek, decrypt_mls_account_secret_backup,
    };
    use crate::recovery_crypto::derive_vault_kek;

    let actor = "did:web:alice.example";
    let device_a = "ak:device:01904100-0000-7000-8000-00000000000a";
    let device_b = "ak:device:01904100-0000-7000-8000-00000000000b";
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000ab";
    let passphrase: &[u8] = b"correct horse battery staple";

    // --- Device A: account secret + a real MLS group + history backup body.
    let store_a = MemorySecureKeyStore::new();
    let secret_a = load_or_create_account_mls_secret(&store_a, actor, device_a).unwrap();

    let identity = ArkretMlsIdentity::new_basic(
        Did::new(actor.to_owned()).unwrap(),
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
        &secret_a,
        b"deterministic-salt",
    );
    let (_history_backup_id, history_body) =
        build_mls_history_backup_body_with_secret(&envelope, actor, device_a, &secret_a, None)
            .unwrap();

    // Device A wraps the account secret behind the recovery PASSPHRASE
    // (KEK derived from the passphrase, exactly like the recovery setup
    // path), so a sibling device can later unwrap it with that passphrase.
    let setup_kek = derive_vault_kek(passphrase).unwrap();
    let account_secret_body = build_mls_account_secret_backup_body_with_kek(
        "ak:backup:01904100-0000-7000-8000-0000000000ac",
        actor,
        device_a,
        &setup_kek,
        &secret_a,
        None,
    )
    .unwrap();

    // --- Device B: a FRESH empty store with NO secret of any kind.
    let store_b = MemorySecureKeyStore::new();
    assert!(
        store_b.is_empty(),
        "device B must start with no local secret"
    );
    // Without the account secret, restore must fail (no local random secret).
    let mut state_b = temp_state_store("xdev-before");
    let pre_restore = restore_mls_history_backup_with_device_snapshot(
        &mut state_b,
        &store_b,
        actor,
        device_b,
        &history_body,
    )
    .unwrap_err();
    assert!(matches!(
        pre_restore,
        MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound)
    ));

    // Recover the account secret with the passphrase and store it on B.
    let recovered = decrypt_mls_account_secret_backup(passphrase, &account_secret_body)
        .expect("correct passphrase unwraps the account secret");
    let recovered_secret = String::from_utf8(recovered).unwrap();
    assert_eq!(recovered_secret, secret_a);
    store_account_mls_secret(&store_b, actor, &recovered_secret).unwrap();

    // Now restore must succeed on B using only the recovered account secret.
    let mut state_b = temp_state_store("xdev-after");
    let summary = restore_mls_history_backup_with_device_snapshot(
        &mut state_b,
        &store_b,
        actor,
        device_b,
        &history_body,
    )
    .expect("restore succeeds once the account secret is recovered");

    // The restored snapshot must match A's group_id / epoch.
    assert_eq!(summary.realm_id, realm);
    assert_eq!(summary.group_id, record.group_id);
    assert_eq!(summary.envelope_epoch, record.epoch);
    let restored_snapshot = state_b.mls_snapshot_for(realm).unwrap();
    assert_eq!(restored_snapshot.group_id, record.group_id);
    assert_eq!(restored_snapshot.epoch, record.epoch);

    // --- Negative: a WRONG passphrase cannot unwrap the account secret, so a
    // fresh device C never gets a usable secret and history stays locked.
    let wrong = decrypt_mls_account_secret_backup(b"incorrect horse", &account_secret_body);
    assert!(wrong.is_err(), "wrong passphrase must fail to unwrap");
    let store_c = MemorySecureKeyStore::new();
    let mut state_c = temp_state_store("xdev-wrong");
    let locked = restore_mls_history_backup_with_device_snapshot(
        &mut state_c,
        &store_c,
        actor,
        device_b,
        &history_body,
    )
    .unwrap_err();
    assert!(matches!(
        locked,
        MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound)
    ));
}
