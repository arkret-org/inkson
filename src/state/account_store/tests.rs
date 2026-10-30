use super::*;

fn path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "inkson-account-{label}-{}.sqlite",
        crate::operation::uuid_v7()
    ))
}
fn put(backend: &Backend, scope: &str, state: ClientLocalState) -> Checkpoint {
    let old = load(backend, scope).unwrap();
    let plan = plan(scope, &old, state).unwrap();
    backend
        .apply_checked_sync(Some(plan.check), plan.deletes, plan.writes)
        .unwrap();
    plan.checkpoint
}
fn state(cursor: &str) -> ClientLocalState {
    let mut state = ClientLocalState {
        sync_cursor: Some(cursor.to_owned()),
        ..Default::default()
    };
    state
        .commit_stream_cursors
        .insert("independent-stream".into(), format!("stream-{cursor}"));
    let checkpoint = garth::mls::checkpoint::encrypt_state(
        "realm",
        "group",
        1,
        cursor.as_bytes(),
        "device-secret",
        b"test-salt",
    );
    state
        .mls_local_checkpoints
        .insert("scope".into(), checkpoint);
    state
        .mls_pending_keypackage_consumes
        .insert("claim".into(), format!("frozen-{cursor}"));
    state
}

#[tokio::test]
async fn physical_transaction_abort_preserves_cursor_current_and_mls_tuple() {
    let path = path("abort");
    let backend = Backend::open_test(path.clone()).await.unwrap();
    let stable = put(&backend, "account", state("old"));
    backend
        .apply_checked_sync(
            None,
            vec![],
            vec![("current-fixture".into(), b"old".to_vec())],
        )
        .unwrap();
    let mut next = state("new");
    next.current_generation = 1;
    let mut plan = plan("account", &stable, next.clone()).unwrap();
    plan.writes
        .insert(0, ("current-fixture".into(), b"new".to_vec()));
    backend.execute_for_test("CREATE TRIGGER fail_record BEFORE INSERT ON current_entries WHEN NEW.key LIKE '%/records/%' BEGIN SELECT RAISE(ABORT,'injected account transaction failure'); END;").unwrap();
    assert!(
        backend
            .apply_checked_sync(
                Some(plan.check.clone()),
                plan.deletes.clone(),
                plan.writes.clone()
            )
            .is_err()
    );
    assert_eq!(
        backend.get_sync("current-fixture").unwrap().unwrap(),
        b"old"
    );
    assert_eq!(load(&backend, "account").unwrap().state, stable.state);
    backend
        .execute_for_test("DROP TRIGGER fail_record")
        .unwrap();
    backend
        .apply_checked_sync(Some(plan.check), plan.deletes, plan.writes)
        .unwrap();
    drop(backend);
    let reopened = Backend::open_test(path).await.unwrap();
    assert_eq!(load(&reopened, "account").unwrap().state, next);
    assert_eq!(
        reopened.get_sync("current-fixture").unwrap().unwrap(),
        b"new"
    );
}

#[tokio::test]
async fn independent_connection_cas_rejects_stale_checkpoint_without_partial_writes() {
    let path = path("cas");
    let first = Backend::open_test(path.clone()).await.unwrap();
    let second = Backend::open_test(path.clone()).await.unwrap();
    let base = put(&first, "account", state("base"));
    let winner = plan("account", &base, state("winner")).unwrap();
    let loser = plan("account", &base, state("loser")).unwrap();
    first
        .apply_checked_sync(Some(winner.check), winner.deletes, winner.writes)
        .unwrap();
    assert!(
        second
            .apply_checked_sync(Some(loser.check), loser.deletes, loser.writes)
            .is_err()
    );
    drop(first);
    drop(second);
    let reopened = Backend::open_test(path).await.unwrap();
    assert_eq!(
        load(&reopened, "account")
            .unwrap()
            .state
            .sync_cursor
            .as_deref(),
        Some("winner")
    );
}

#[tokio::test]
async fn bounded_gc_resumes_after_reopen_and_never_collects_a_live_blob() {
    let path = path("gc");
    let backend = Backend::open_test(path.clone()).await.unwrap();
    let mut initial = state("one");
    initial
        .plain_local_data
        .insert("large".into(), "x".repeat(CHUNK_BYTES * 103));
    let old = put(&backend, "account", initial);
    let data_scope = item_scope("account", &old.incarnation).unwrap();
    let old_blob = old.records[&vec!["plain_local_data".into(), "large".into()]]
        .blob
        .clone();
    let mut next = old.state.clone();
    next.plain_local_data.insert("large".into(), "live".into());
    let committed = put(&backend, "account", next.clone());
    let live_blob = committed.records[&vec!["plain_local_data".into(), "large".into()]]
        .blob
        .clone();
    backend.execute_for_test("CREATE TRIGGER fail_gc BEFORE DELETE ON current_entries WHEN OLD.key LIKE '%/chunks/%' BEGIN SELECT RAISE(ABORT,'injected GC failure'); END;").unwrap();
    assert!(gc(&backend, "account").is_err());
    assert!(
        backend
            .get_sync(&chunk_key(&data_scope, &old_blob, 0))
            .unwrap()
            .is_some()
    );
    backend.execute_for_test("DROP TRIGGER fail_gc").unwrap();
    assert!(gc(&backend, "account").unwrap());
    let tasks = backend
        .scan_sync(&format!("{}gc/", prefix("account")), None, 100)
        .unwrap();
    assert!(
        !tasks.is_empty(),
        "one maintenance slice must remain bounded"
    );
    drop(backend);
    let reopened = Backend::open_test(path).await.unwrap();
    let mut slices = 0;
    while gc(&reopened, "account").unwrap() {
        slices += 1;
        assert!(slices < 20);
    }
    assert!(
        reopened
            .scan_sync(
                &format!("{}chunks/{old_blob}/", prefix(&data_scope)),
                None,
                100
            )
            .unwrap()
            .is_empty()
    );
    assert!(
        reopened
            .get_sync(&chunk_key(&data_scope, &live_blob, 0))
            .unwrap()
            .is_some()
    );
    assert_eq!(load(&reopened, "account").unwrap().state, next);
}

#[tokio::test]
async fn missing_or_unauthenticated_chunk_fails_closed_and_retains_root() {
    let backend = Backend::open_test(path("corrupt")).await.unwrap();
    let committed = put(&backend, "account", state("protected"));
    let root = backend.get_sync(&root_key("account")).unwrap();
    let data_scope = item_scope("account", &committed.incarnation).unwrap();
    let record = &committed.records[&vec!["sync_cursor".into()]];
    let key = chunk_key(&data_scope, &record.blob, 0);
    backend.apply_checked_sync(None, vec![key], vec![]).unwrap();
    assert!(load(&backend, "account").is_err());
    assert_eq!(backend.get_sync(&root_key("account")).unwrap(), root);
    assert!(
        backend
            .scan_sync(&format!("{}records/", prefix(&data_scope)), None, 100)
            .unwrap()
            .len()
            > 1
    );
}

#[tokio::test]
async fn nested_empty_collections_and_deletes_round_trip_without_resurrecting_children() {
    let backend = Backend::open_test(path("nested")).await.unwrap();
    let mut initial = state("nested");
    initial
        .member_identity_events
        .entry("realm".into())
        .or_default()
        .insert(
            "actor".into(),
            vec![serde_json::json!({"event_id":"one"})].into(),
        );
    initial
        .member_identity_events
        .insert("empty-realm".into(), imbl::OrdMap::new());
    initial.mls_genesis_emitted.insert("scope".into());
    put(&backend, "account", initial.clone());
    assert_eq!(load(&backend, "account").unwrap().state, initial);
    initial
        .member_identity_events
        .get_mut("realm")
        .unwrap()
        .remove("actor");
    initial.mls_genesis_emitted.remove("scope");
    put(&backend, "account", initial.clone());
    assert_eq!(load(&backend, "account").unwrap().state, initial);
    initial.member_identity_events.remove("realm");
    put(&backend, "account", initial.clone());
    while gc(&backend, "account").unwrap() {}
    assert_eq!(load(&backend, "account").unwrap().state, initial);
}

#[tokio::test]
async fn one_principal_at_two_stations_has_independent_transactions_and_gc() {
    let backend = Backend::open_test(path("stations")).await.unwrap();
    let a = crate::test_support::authority_at_station(
        "did:web:alice.example",
        "did:web:station-a.example",
    );
    let b = crate::test_support::authority_at_station(
        "did:web:alice.example",
        "did:web:station-b.example",
    );
    let a = super::super::account_storage_scope(&a).unwrap();
    let b = super::super::account_storage_scope(&b).unwrap();
    assert_ne!(a, b);
    put(&backend, &a, state("a"));
    put(&backend, &b, state("b"));
    put(&backend, &a, ClientLocalState::default());
    while gc(&backend, &a).unwrap() {}
    assert_eq!(
        load(&backend, &b).unwrap().state.sync_cursor.as_deref(),
        Some("b")
    );
}

#[tokio::test]
async fn product_stage_is_memory_only_and_joins_the_real_account_transaction() {
    use super::super::{CurrentIndex, LocalStateStore};
    let path = path("publication").with_extension("json");
    let mut store = LocalStateStore::with_path(&path);
    store.switch_test_account("did:web:alice.example");
    let account = store.active_authority().unwrap();
    let scope = super::super::account_storage_scope(&account).unwrap();
    let index = CurrentIndex::open(&account, 0, store.current_index_location())
        .await
        .unwrap();
    let frame = serde_json::from_value(serde_json::json!({"kind":"resync_required"})).unwrap();
    let mut stage = index.stage_frame(0, &frame).await.unwrap();
    stage.arm_account_commit();
    let publication = CurrentIndex::account_publication(
        store.current_index_location(),
        &account,
        stage.generation(),
    )
    .unwrap()
    .unwrap();
    let backend = store.account_record_backend().unwrap();
    for (key, _) in publication.writes.iter() {
        assert!(backend.get_sync(key).unwrap().is_none());
    }
    backend.execute_for_test("CREATE TRIGGER fail_cursor BEFORE INSERT ON current_entries WHEN NEW.key LIKE 'inkson.current.v1/accounts/roots/%' BEGIN SELECT RAISE(ABORT,'account root failure'); END;").unwrap();
    let result = store.verified_projection_transaction(|store| {
        store.set_current_generation(stage.generation());
        store.save_sync_cursor("together");
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(load(&backend, &scope).unwrap().state.current_generation, 0);
    for (key, _) in publication.writes.iter() {
        assert!(backend.get_sync(key).unwrap().is_none());
    }
    backend
        .execute_for_test("DROP TRIGGER fail_cursor")
        .unwrap();
    store
        .verified_projection_transaction(|store| {
            store.set_current_generation(stage.generation());
            store.save_sync_cursor("together");
            Ok(())
        })
        .unwrap();
    store.begin_durable_flush().unwrap().wait().await.unwrap();
    let reopened = LocalStateStore::with_path(&path).load();
    assert_eq!(reopened.sync_cursor.as_deref(), Some("together"));
    assert_eq!(reopened.current_generation, stage.generation());
    for (key, value) in publication.writes.iter() {
        assert_eq!(backend.get_sync(key).unwrap().as_ref(), Some(value));
    }
    stage.finish();
}

#[test]
fn process_crash_during_sqlite_account_transaction_restores_the_last_committed_cut() {
    use std::process::{Command, Stdio};
    if let Some(database) = std::env::var_os("INKSON_TEST_ACCOUNT_TX_DATABASE") {
        let backend = Backend::open_sync(CurrentIndexLocation {
            path: database.into(),
        })
        .unwrap();
        let old = load(&backend, "account").unwrap();
        let mut plan = plan("account", &old, state("interrupted")).unwrap();
        plan.writes
            .insert(0, ("crash-current".into(), b"interrupted".to_vec()));
        backend
            .apply_checked_sync(Some(plan.check), plan.deletes, plan.writes)
            .unwrap();
        panic!("crash fixture unexpectedly completed");
    }
    let database = path("process-crash");
    let ready = database.with_extension("ready");
    let backend = Backend::open_sync(CurrentIndexLocation {
        path: database.clone(),
    })
    .unwrap();
    let stable = put(&backend, "account", state("stable"));
    backend
        .apply_checked_sync(
            None,
            vec![],
            vec![("crash-current".into(), b"stable".to_vec())],
        )
        .unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact","state::account_store::tests::process_crash_during_sqlite_account_transaction_restores_the_last_committed_cut","--nocapture"])
        .env("INKSON_TEST_ACCOUNT_TX_DATABASE",&database).env("INKSON_TEST_PAUSE_ACCOUNT_TX",&ready)
        .stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x08000000);
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(command.spawn().unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "crash fixture exited before opening its transaction"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "crash fixture never opened its transaction"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    drop(backend);
    let reopened = Backend::open_sync(CurrentIndexLocation { path: database }).unwrap();
    assert_eq!(load(&reopened, "account").unwrap().state, stable.state);
    assert_eq!(
        reopened.get_sync("crash-current").unwrap().as_deref(),
        Some(b"stable".as_slice())
    );
}

#[tokio::test]
async fn record_set_root_rejects_missing_and_replayed_records_even_with_valid_old_ciphertext() {
    let backend = Backend::open_test(path("record-set")).await.unwrap();
    let mut initial = state("same-cursor");
    initial
        .plain_local_data
        .insert("protected".into(), "before".into());
    let old = put(&backend, "account", initial.clone());
    let data_scope = item_scope("account", &old.incarnation).unwrap();
    let key = record_key(
        &data_scope,
        &["plain_local_data".into(), "protected".into()],
    )
    .unwrap();
    let old_pointer = backend.get_sync(&key).unwrap().unwrap();
    initial
        .plain_local_data
        .insert("protected".into(), "after".into());
    let new = put(&backend, "account", initial);
    let new_pointer = backend.get_sync(&key).unwrap().unwrap();
    let root = backend.get_sync(&root_key("account")).unwrap();
    backend
        .apply_checked_sync(None, vec![], vec![(key.clone(), old_pointer)])
        .unwrap();
    assert!(load(&backend, "account").is_err());
    assert!(committed_map::<String>(&backend, "account", "plain_local_data", None, &new).is_err());
    assert_eq!(backend.get_sync(&root_key("account")).unwrap(), root);
    backend
        .apply_checked_sync(None, vec![], vec![(key.clone(), new_pointer)])
        .unwrap();
    assert_eq!(load(&backend, "account").unwrap().state, new.state);
    backend.apply_checked_sync(None, vec![key], vec![]).unwrap();
    assert!(load(&backend, "account").is_err());
    assert!(committed_map::<String>(&backend, "account", "plain_local_data", None, &new).is_err());
}
