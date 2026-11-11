//! Production allocator and durable seal/reopen regression tests.

use std::path::PathBuf;

use super::*;

fn directory() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/signal-endpoint-tests")
        .join(crate::operation::uuid_v7());
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn event(seed: u8) -> arkret_sdk::EventId {
    arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [seed; 32])
}

#[test]
fn nonce_journal_burns_before_seal_and_rejects_missing_rollback_and_torn_tail() {
    let path = directory().join("reservations.jsonl");
    assert_eq!(
        reserve_signal_counter_block_in_file(&path, "nonce:test", 1, 0, true).unwrap(),
        0
    );
    // No checkpoint/HTTP write occurred, yet restart cannot reuse the value.
    assert_eq!(
        reserve_signal_counter_block_in_file(&path, "nonce:test", 1, 0, true).unwrap(),
        1
    );
    assert!(reserve_signal_counter_block_in_file(&path, "nonce:test", 1, 9, false).is_err());
    assert!(reserve_signal_counter_block_in_file(&path, "nonce:lost", 1, 2, false).is_err());
    assert_eq!(
        reserve_signal_sequence_block_in_file(&path, "business:test", 256).unwrap(),
        1
    );
    assert_eq!(
        reserve_signal_counter_block_in_file(&path, "nonce:test", 1, 2, false).unwrap(),
        2
    );
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"version\":1")
        .unwrap();
    assert!(reserve_signal_counter_block_in_file(&path, "nonce:test", 1, 3, false).is_err());
}

#[test]
fn nonce_journal_rejects_record_rollback_and_overflow() {
    let path = directory().join("reservations.jsonl");
    reserve_signal_counter_block_in_file(&path, "nonce:test", 1, 0, true).unwrap();
    use std::io::Write as _;
    let record = serde_json::to_vec(&SignalSequenceReservationRecord {
        version: 1,
        domain: "nonce:test".into(),
        next_unreserved: 1,
    })
    .unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(&record).unwrap();
    file.write_all(b"\n").unwrap();
    assert!(reserve_signal_counter_block_in_file(&path, "nonce:test", 1, 1, false).is_err());
    let path = directory().join("exhausted.jsonl");
    assert!(reserve_signal_counter_block_in_file(&path, "nonce:test", 1, u64::MAX, true).is_err());
}

#[test]
#[ignore = "subprocess worker for production file-lock allocation"]
fn signal_nonce_process_worker() {
    let path = PathBuf::from(
        std::env::var_os("INKSON_SIGNAL_NONCE_TEST_JOURNAL").expect("worker journal"),
    );
    if std::env::var_os("INKSON_SIGNAL_NONCE_TEST_EXIT_AFTER_RESERVE").is_some() {
        reserve_signal_counter_block_in_file(&path, "nonce:abrupt-exit", 1, 0, true).unwrap();
        // Exit without Rust destructors or any MLS checkpoint/publication.
        std::process::exit(73);
    }
    for _ in 0..16 {
        reserve_signal_counter_block_in_file(&path, "nonce:shared-processes", 1, 0, true).unwrap();
    }
}

#[test]
fn nonce_reservation_survives_abrupt_process_exit_before_checkpoint() {
    let path = directory().join("abrupt-exit.jsonl");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "signal::nonce_tests::signal_nonce_process_worker",
            "--ignored",
        ])
        .env("INKSON_SIGNAL_NONCE_TEST_JOURNAL", &path)
        .env("INKSON_SIGNAL_NONCE_TEST_EXIT_AFTER_RESERVE", "1")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    assert_eq!(
        reserve_signal_counter_block_in_file(&path, "nonce:abrupt-exit", 1, 0, true).unwrap(),
        1
    );
}

#[test]
fn nonce_reservations_are_unique_across_real_processes() {
    let path = directory().join("processes.jsonl");
    let mut children = (0..4)
        .map(|_| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "signal::nonce_tests::signal_nonce_process_worker",
                    "--ignored",
                ])
                .env("INKSON_SIGNAL_NONCE_TEST_JOURNAL", &path)
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let text = std::fs::read_to_string(path).unwrap();
    let values = text
        .lines()
        .map(|line| {
            serde_json::from_str::<SignalSequenceReservationRecord>(line)
                .unwrap()
                .next_unreserved
        })
        .collect::<Vec<_>>();
    assert_eq!(values, (1..=64).collect::<Vec<_>>());
}

#[tokio::test]
async fn signal_seal_commits_checkpoint_and_restart_and_stale_snapshot_do_not_reuse_nonce() {
    let path = directory().join("client.json");
    let mut store = crate::state::LocalStateStore::with_path(path.clone());
    store.switch_test_account("did:web:signal-persistence.example");
    let authority = store.active_authority().unwrap();
    let actor = arkret_sdk::ActorId::account(authority.clone());
    let device =
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000076").unwrap();
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::from_event_id(&event(81)),
    };
    let identity = arkret_sdk::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        device.clone(),
        arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[81; 32]),
        ),
    )
    .unwrap();
    let mut group = identity.create_group(&scope).unwrap();
    group
        .install_local_creator_binding(actor.clone(), Some(event(82)))
        .unwrap();
    let record = group.export_state_record().unwrap();
    let secure = crate::secure_key_store::MemorySecureKeyStore::default();
    let secret =
        crate::mls::runtime::load_or_create_account_mls_secret(&secure, &authority).unwrap();
    let mut checkpoint = garth::mls::checkpoint::encrypt_state(
        scope.realm_id().as_str(),
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        &secret,
        &[81; 16],
    );
    checkpoint.group_state_event_id = Some(event(83));
    store
        .save_signal_mls_checkpoint(&scope, checkpoint.clone())
        .unwrap()
        .wait()
        .await
        .unwrap();
    let shared = std::sync::Arc::new(std::sync::Mutex::new(store));
    let read = shared.clone();
    let write = shared.clone();
    let handle = crate::runtime::input::StateStoreHandle::new(
        move |callback| callback(&read.lock().unwrap()),
        move |callback| callback(&mut write.lock().unwrap()),
    );
    let header = SignalHeader::new(
        scope.clone(),
        actor.clone(),
        device.clone(),
        arkret_sdk::RealmCommitId::from_digest([81; 32]),
        None,
        arkret_wire::SignalClass::Session,
        crate::clock::now_utc(),
    );
    let material = SignalKeyMaterial {
        group_state_ref: event(83).to_string(),
        epoch: 0,
        aead_profile: arkret_sdk::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.into(),
    };
    let first = encrypt_signal_payload_with_store(
        &handle,
        &secure,
        &authority,
        &header,
        &material,
        b"before restart",
    )
    .await
    .unwrap();
    let disk = crate::state::LocalStateStore::with_path(path);
    let restored =
        restore_signal_mls_session(&disk, &secure, &scope, &authority, &device, 0).unwrap();
    assert_eq!(restored.group.signal_nonce_counter(), 1);
    // A stale MLS checkpoint cannot rewind the independent reservation journal.
    let barrier = shared
        .lock()
        .unwrap()
        .save_signal_mls_checkpoint(&scope, checkpoint)
        .unwrap();
    barrier.wait().await.unwrap();
    let second = encrypt_signal_payload_with_store(
        &handle,
        &secure,
        &authority,
        &header,
        &material,
        b"after stale snapshot",
    )
    .await
    .unwrap();
    assert_ne!(first.nonce, second.nonce);
    let context = shared
        .lock()
        .unwrap()
        .signal_sequence_store_context(&actor)
        .unwrap();
    std::fs::remove_file(&context.path).unwrap();
    assert!(
        encrypt_signal_payload_with_store(
            &handle,
            &secure,
            &authority,
            &header,
            &material,
            b"lost allocator"
        )
        .await
        .is_err()
    );
}
