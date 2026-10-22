use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::*;

type Checkpoint = garth::mls::checkpoint::MlsLocalCheckpointEnvelope;

fn fixture() -> (LocalStateStore, arkret_sdk::ScopeRef, Checkpoint) {
    let path = std::env::temp_dir().join(format!(
        "inkson-committed-read-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut store = LocalStateStore::with_path(path);
    store.switch_test_account("did:web:alice.example");
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new("ak:realm:AR9U75vD82XqGon9r2GYv6cwT3_W8U4BtjeOCoODErj_")
            .unwrap(),
    };
    let checkpoint = checkpoint(&scope, 1);
    store
        .save_mls_checkpoint_for_scope(&scope, checkpoint.clone())
        .unwrap();
    (store, scope, checkpoint)
}

fn checkpoint(scope: &arkret_sdk::ScopeRef, epoch: u64) -> Checkpoint {
    garth::mls::checkpoint::encrypt_state(
        scope.realm_id().as_str(),
        scope.canonical_mls_group_id().unwrap().as_str(),
        epoch,
        &[epoch as u8],
        "device-secret",
        b"read-race-salt",
    )
}

fn handle(
    store: LocalStateStore,
    change: impl Fn(&mut LocalStateStore, usize) + Send + Sync + 'static,
) -> (StateStoreHandle, Arc<AtomicUsize>) {
    let store = Arc::new(Mutex::new(store));
    let read = store.clone();
    let write = store;
    let reads = Arc::new(AtomicUsize::new(0));
    let count = reads.clone();
    let state = StateStoreHandle::new(
        move |callback| {
            let mut store = read.lock().unwrap();
            callback(&store);
            // Commit after the captured read has left its store borrow, as a
            // background account writer can do while its I/O is pending.
            change(&mut store, count.fetch_add(1, Ordering::SeqCst) + 1);
        },
        move |callback| callback(&mut write.lock().unwrap()),
    );
    (state, reads)
}

#[tokio::test]
async fn stable_committed_checkpoint_needs_no_resampling() {
    let (store, scope, expected) = fixture();
    let (state, reads) = handle(store, |_, _| {});
    assert_eq!(
        read_durable_checkpoint(&state, &scope).await.unwrap(),
        Some(expected)
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unrelated_committed_write_discards_the_old_read_and_keeps_the_checkpoint() {
    let (store, scope, expected) = fixture();
    let (state, reads) = handle(store, |store, read| {
        if read == 1 {
            store.append_raw_operation("unrelated", None, serde_json::json!({"background": true}));
            store.flush().unwrap();
        }
    });
    assert_eq!(
        read_durable_checkpoint(&state, &scope).await.unwrap(),
        Some(expected)
    );
    assert_eq!(reads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_new_committed_cut_is_read_whole_instead_of_returning_the_old_checkpoint() {
    let (store, scope, initial) = fixture();
    let changed = checkpoint(&scope, 2);
    let mut expected = changed.clone();
    // Advancing the checkpoint retains the scope's original admission floor.
    expected.admission_epoch = initial.admission_epoch;
    let changed_scope = scope.clone();
    let (state, reads) = handle(store, move |store, read| {
        if read == 1 {
            store.set_current_generation(store.current_generation() + 1);
            store
                .save_mls_checkpoint_for_scope(&changed_scope, changed.clone())
                .unwrap();
            store.flush().unwrap();
        }
    });
    assert_eq!(
        read_durable_checkpoint(&state, &scope).await.unwrap(),
        Some(expected)
    );
    assert_eq!(reads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn account_replacement_never_rebinds_the_old_read_to_the_new_account() {
    let (store, scope, _) = fixture();
    let (state, reads) = handle(store, |store, read| {
        if read == 1 {
            store.switch_test_account("did:web:bob.example");
        }
    });
    let error = read_durable_checkpoint(&state, &scope).await.unwrap_err();
    assert!(error.to_string().contains("replaced session"));
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn continuous_commit_churn_remains_bounded_and_returns_no_consume_result() {
    let (store, ..) = fixture();
    let (state, reads) = handle(store, |store, read| {
        store.append_raw_operation(
            format!("unrelated-{read}"),
            None,
            serde_json::json!({"background": read}),
        );
        store.flush().unwrap();
    });
    let error = read_durable_consumes(&state).await.unwrap_err();
    assert!(error.to_string().contains("repeatedly changed"));
    assert_eq!(reads.load(Ordering::SeqCst), COMMITTED_READ_ATTEMPTS + 1);
}
