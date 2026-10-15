//! Browser contracts use the product IndexedDB port and account writer.
use anyhow::Context as _;

use super::*;

fn unique(label: &str) -> String {
    format!("contract-{label}-{}", crate::operation::uuid_v7())
}
fn state(cursor: &str) -> ClientLocalState {
    let mut state = ClientLocalState {
        sync_cursor: Some(cursor.to_owned()),
        ..Default::default()
    };
    state
        .commit_stream_cursors
        .insert("stream".into(), format!("stream-{cursor}"));
    state.mls_local_checkpoints.insert(
        "scope".into(),
        garth::mls::checkpoint::encrypt_state(
            "realm",
            "group",
            1,
            cursor.as_bytes(),
            "device-secret",
            b"contract-salt",
        ),
    );
    state
        .mls_pending_keypackage_consumes
        .insert("claim".into(), format!("original-signed-{cursor}"));
    state
}
async fn commit(
    backend: &Backend,
    scope: &str,
    state: ClientLocalState,
) -> anyhow::Result<Checkpoint> {
    let old = load_async(backend, scope).await?;
    let plan = plan(scope, &old, state)?;
    backend
        .apply_checked(Some(plan.check), plan.deletes, plan.writes)
        .await?;
    Ok(plan.checkpoint)
}

pub(super) async fn run() -> anyhow::Result<()> {
    crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await?;
    transaction_abort_and_independent_cas()
        .await
        .context("account transaction abort/CAS")?;
    product_publication_and_cancelled_waiter()
        .await
        .context("product account publication")?;
    gc_restart().await.context("account GC restart")?;
    capacity()
        .await
        .context("account bounded physical writes")?;
    anonymous_repair_resume()
        .await
        .context("anonymous repair restart")?;
    Ok(())
}

async fn transaction_abort_and_independent_cas() -> anyhow::Result<()> {
    let scope = unique("atomic");
    let backend = Backend::open(CurrentIndexLocation {}).await?;
    let stable = commit(&backend, &scope, state("old")).await?;
    let current_key = format!(
        "{}contract-current/{scope}",
        super::super::current_index::CURRENT_PREFIX
    );
    backend
        .apply(vec![], vec![(current_key.clone(), b"old".to_vec())])
        .await?;
    let mut next = state("new");
    next.current_generation = 1;
    let mut plan = plan(&scope, &stable, next.clone())?;
    plan.writes
        .insert(0, (current_key.clone(), b"new".to_vec()));
    Backend::abort_account_transaction_for_test(root_key(&scope));
    anyhow::ensure!(
        backend
            .apply_checked(
                Some(plan.check.clone()),
                plan.deletes.clone(),
                plan.writes.clone()
            )
            .await
            .is_err(),
        "injected transaction committed"
    );
    let reopened = Backend::open(CurrentIndexLocation {}).await?;
    anyhow::ensure!(
        load_async(&reopened, &scope).await?.state == stable.state,
        "abort advanced cursor or MLS tuple"
    );
    anyhow::ensure!(
        reopened.get(&current_key).await?.as_deref() == Some(b"old"),
        "abort advanced current data"
    );
    backend
        .apply_checked(Some(plan.check), plan.deletes, plan.writes)
        .await?;
    anyhow::ensure!(
        load_async(&reopened, &scope).await?.state == next,
        "reopen lost jointly committed data"
    );
    let decrypted = garth::mls::checkpoint::decrypt_envelope(
        &next.mls_local_checkpoints["scope"],
        "device-secret",
    )?;
    anyhow::ensure!(decrypted == b"new", "MLS recovery bytes changed");

    let base = load_async(&reopened, &scope).await?;
    let mut a_state = state("writer-a");
    a_state.current_generation = 1;
    let mut b_state = state("writer-b");
    b_state.current_generation = 1;
    let a = super::plan(&scope, &base, a_state.clone())?;
    let b = super::plan(&scope, &base, b_state.clone())?;
    let other = Backend::open(CurrentIndexLocation {}).await?;
    let (a, b) = tokio::join!(
        backend.apply_checked(Some(a.check), a.deletes, a.writes),
        other.apply_checked(Some(b.check), b.deletes, b.writes)
    );
    anyhow::ensure!(
        a.is_ok() != b.is_ok(),
        "independent handles did not enforce transaction CAS"
    );
    let winner = load_async(&reopened, &scope).await?.state;
    anyhow::ensure!(
        winner == if a.is_ok() { a_state } else { b_state },
        "losing writer partially changed the winner"
    );
    Ok(())
}

struct RootRestore(super::super::RootIndex);
impl Drop for RootRestore {
    fn drop(&mut self) {
        let _ = super::super::LocalStateStore::default().write_root(&self.0);
    }
}

async fn product_publication_and_cancelled_waiter() -> anyhow::Result<()> {
    use super::super::{CurrentIndex, LocalStateStore};
    let mut store = LocalStateStore::default();
    let _restore = RootRestore(store.read_root());
    let account = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{}.example", unique("holder")))?,
        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example")?,
    );
    let scope = super::super::account_storage_scope(&account)?;
    browser::hydrate(&scope).await?;
    store.mutate_root(|root| {
        let profile = format!("profile-{scope}");
        root.pending_login = None;
        root.active_profile_id = Some(profile.clone());
        root.note_known_profile(super::super::AccountIndexEntry {
            profile_id: profile,
            authority: account.clone(),
        });
    });
    store.ensure_cached_loaded();
    store.begin_durable_flush()?.wait().await?;
    let index = CurrentIndex::open(&account, 0, store.current_index_location()).await?;
    let frame = serde_json::from_value(serde_json::json!({"kind":"resync_required"}))?;
    let mut stage = index.stage_frame(0, &frame).await?;
    stage.arm_account_commit();
    let publication = CurrentIndex::account_publication(
        store.current_index_location(),
        &account,
        stage.generation(),
    )?
    .context("missing bound current publication")?;
    let backend = Backend::open(CurrentIndexLocation {}).await?;
    for (key, _) in publication.writes.iter() {
        anyhow::ensure!(
            backend.get(key).await?.is_none(),
            "staging wrote durable current data"
        );
    }
    Backend::abort_account_transaction_for_test(root_key(&scope));
    store
        .verified_projection_transaction(|store| {
            store.set_current_generation(stage.generation());
            store.save_sync_cursor("atomic-current");
            Ok(())
        })
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        store.capture_committed_account_read().is_err(),
        "optimistic current generation authorized a committed read"
    );
    anyhow::ensure!(
        store.begin_durable_flush()?.wait().await.is_err(),
        "failed predecessor satisfied a durable barrier"
    );
    let cold = load_async(&Backend::open(CurrentIndexLocation {}).await?, &scope).await?;
    anyhow::ensure!(
        cold.state.current_generation == 0 && cold.state.sync_cursor.is_none(),
        "failed product write advanced its root"
    );
    for (key, _) in publication.writes.iter() {
        anyhow::ensure!(
            backend.get(key).await?.is_none(),
            "failed product transaction left current rows"
        );
    }
    store.begin_durable_flush()?.wait().await?;
    let generation = stage.generation();
    stage.finish();
    drop(publication);
    let cold = load_async(&Backend::open(CurrentIndexLocation {}).await?, &scope).await?;
    anyhow::ensure!(
        cold.state.current_generation == generation
            && cold.state.sync_cursor.as_deref() == Some("atomic-current"),
        "product restart lost its coherent current/cursor"
    );

    let mut stage = index.stage_frame(generation, &frame).await?;
    stage.arm_account_commit();
    let next = stage.generation();
    store
        .verified_projection_transaction(|store| {
            store.set_current_generation(next);
            store.save_sync_cursor("cancelled-waiter");
            Ok(())
        })
        .map_err(anyhow::Error::msg)?;
    drop(store.begin_durable_flush()?);
    drop(stage);
    let deadline = js_sys::Date::now() + 20_000.0;
    loop {
        let cold = load_async(&backend, &scope).await?;
        if cold.state.current_generation == next {
            anyhow::ensure!(
                cold.state.sync_cursor.as_deref() == Some("cancelled-waiter"),
                "cancelled waiter split its cursor"
            );
            break;
        }
        anyhow::ensure!(
            js_sys::Date::now() < deadline,
            "independent account writer stopped with its waiter"
        );
        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(5)).await;
    }
    let reopened = CurrentIndex::open(&account, next, store.current_index_location()).await?;
    reopened.confirm_durable_pointer(next)?;
    browser::hydrate(&scope).await?;
    let fresh = LocalStateStore::default().load();
    anyhow::ensure!(
        fresh.current_generation == next
            && fresh.sync_cursor.as_deref() == Some("cancelled-waiter"),
        "fresh host did not recover committed state"
    );
    Ok(())
}

async fn gc_restart() -> anyhow::Result<()> {
    let scope = unique("gc");
    let backend = Backend::open(CurrentIndexLocation {}).await?;
    let mut initial = state("gc");
    initial
        .plain_local_data
        .insert("large".into(), "x".repeat(CHUNK_BYTES * 103));
    let old = commit(&backend, &scope, initial).await?;
    let data_scope = item_scope(&scope, &old.incarnation)?;
    let old_blob = old.records[&vec!["plain_local_data".into(), "large".into()]]
        .blob
        .clone();
    let mut next = old.state.clone();
    next.plain_local_data.insert("large".into(), "live".into());
    commit(&backend, &scope, next.clone()).await?;
    anyhow::ensure!(
        gc_async(&backend, &scope).await?,
        "GC found no retired blob"
    );
    anyhow::ensure!(
        !backend
            .keys(&format!("{}gc/", prefix(&scope)), None, None, 100)
            .await?
            .is_empty(),
        "GC ignored its slice bound"
    );
    backend.close_for_test();
    let reopened = Backend::open(CurrentIndexLocation {}).await?;
    let mut slices = 0;
    while gc_async(&reopened, &scope).await? {
        slices += 1;
        anyhow::ensure!(slices < 20, "GC did not converge");
    }
    anyhow::ensure!(
        reopened
            .keys(
                &format!("{}chunks/{old_blob}/", prefix(&data_scope)),
                None,
                None,
                100
            )
            .await?
            .is_empty(),
        "restart retained unreachable blob chunks"
    );
    anyhow::ensure!(
        load_async(&reopened, &scope).await?.state == next,
        "GC removed live state"
    );
    Ok(())
}

async fn capacity() -> anyhow::Result<()> {
    let mut expected: Option<(usize, usize)> = None;
    for count in [1, 100, 1000] {
        let scope = arkret_sdk::canonical::sha256_base64url(unique(&format!("capacity-{count}")));
        let backend = Backend::open(CurrentIndexLocation {}).await?;
        let mut initial = ClientLocalState::default();
        for i in 0..count {
            let realm = format!("realm-{i}");
            initial.realm_tree_projections.insert(
                realm.clone(),
                serde_json::json!({"summary":"x".repeat(256)}),
            );
            initial
                .member_identity_events
                .entry(realm)
                .or_default()
                .insert(
                    format!("actor-{i}"),
                    vec![serde_json::json!({"identity":"y".repeat(128)})].into(),
                );
        }
        let old = commit(&backend, &scope, initial).await?;
        let mut next = old.state.clone();
        next.sync_cursor = Some("bounded".into());
        let plan = plan(&scope, &old, next.clone())?;
        let size = (
            plan.writes.len(),
            plan.writes
                .iter()
                .map(|(_, value)| value.len())
                .sum::<usize>(),
        );
        anyhow::ensure!(size.0 == 3, "cursor transaction rewrote unrelated records");
        if let Some(expected) = expected {
            anyhow::ensure!(
                size.0 == expected.0 && size.1 <= expected.1 + 20 && size.1 <= 1024,
                "physical cursor write grew with Realm/member count"
            );
        } else {
            expected = Some(size);
        }
        backend
            .apply_checked(Some(plan.check), plan.deletes, plan.writes)
            .await?;
        let fresh = load_async(&Backend::open(CurrentIndexLocation {}).await?, &scope).await?;
        anyhow::ensure!(
            fresh.state == next,
            "capacity restart changed committed data"
        );
    }
    Ok(())
}

pub(super) async fn corruption() -> anyhow::Result<()> {
    crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await?;
    let scope = unique("corrupt");
    let backend = Backend::open(CurrentIndexLocation {}).await?;
    let committed = commit(&backend, &scope, state("protected")).await?;
    let root = backend.get(&root_key(&scope)).await?;
    let data_scope = item_scope(&scope, &committed.incarnation)?;
    let record = &committed.records[&vec!["sync_cursor".into()]];
    backend
        .apply(vec![chunk_key(&data_scope, &record.blob, 0)], vec![])
        .await?;
    let reopened = Backend::open(CurrentIndexLocation {}).await?;
    anyhow::ensure!(
        load_async(&reopened, &scope).await.is_err(),
        "missing committed chunk was replaced by defaults"
    );
    anyhow::ensure!(
        reopened.get(&root_key(&scope)).await? == root,
        "failed hydration overwrote its durable root"
    );
    let scope = unique("record-set");
    let mut initial = state("same-cursor");
    initial
        .plain_local_data
        .insert("protected".into(), "before".into());
    let old = commit(&backend, &scope, initial.clone()).await?;
    let data_scope = item_scope(&scope, &old.incarnation)?;
    let key = record_key(
        &data_scope,
        &["plain_local_data".into(), "protected".into()],
    )?;
    let old_pointer = backend.get(&key).await?.context("old pointer missing")?;
    initial
        .plain_local_data
        .insert("protected".into(), "after".into());
    let update = plan(&scope, &old, initial)?;
    let new = update.checkpoint.clone();
    backend
        .apply_checked(Some(update.check), update.deletes, update.writes)
        .await?;
    let new_pointer = backend.get(&key).await?.context("new pointer missing")?;
    let root = backend.get(&root_key(&scope)).await?;
    backend
        .apply(vec![], vec![(key.clone(), old_pointer)])
        .await?;
    anyhow::ensure!(
        load_async(&backend, &scope).await.is_err(),
        "replayed record accepted"
    );
    anyhow::ensure!(
        committed_read::committed_map_async::<String>(
            &backend,
            &scope,
            "plain_local_data",
            None,
            &new
        )
        .await
        .is_err(),
        "narrow read accepted replayed record"
    );
    anyhow::ensure!(
        backend.get(&root_key(&scope)).await? == root,
        "replay failure changed root"
    );
    backend
        .apply(vec![], vec![(key.clone(), new_pointer)])
        .await?;
    anyhow::ensure!(
        load_async(&backend, &scope).await?.state == new.state,
        "restored record differs"
    );
    backend.apply(vec![key], vec![]).await?;
    anyhow::ensure!(
        load_async(&backend, &scope).await.is_err(),
        "missing record accepted"
    );
    anyhow::ensure!(
        committed_read::committed_map_async::<String>(
            &backend,
            &scope,
            "plain_local_data",
            None,
            &new
        )
        .await
        .is_err(),
        "narrow read accepted missing record"
    );
    Ok(())
}

async fn anonymous_repair_resume() -> anyhow::Result<()> {
    use super::super::{ANONYMOUS_ACCOUNT_NAMESPACE, LocalStateStore, PendingLogin};
    let store = LocalStateStore::default();
    let _restore = RootRestore(store.read_root());
    let backend = Backend::open(CurrentIndexLocation {}).await?;
    let old = commit(&backend, ANONYMOUS_ACCOUNT_NAMESPACE, state("quarantined")).await?;
    let old_data = item_scope(ANONYMOUS_ACCOUNT_NAMESPACE, &old.incarnation)?;
    backend
        .apply(
            vec![],
            vec![(
                root_key(ANONYMOUS_ACCOUNT_NAMESPACE),
                b"{truncated".to_vec(),
            )],
        )
        .await?;
    let raw = backend
        .raw(&root_key(ANONYMOUS_ACCOUNT_NAMESPACE))
        .await?
        .context("unreadable root ciphertext missing")?;
    let incarnation = crate::operation::uuid_v7();
    store.mutate_root(|root| {
        root.pending_login = Some(PendingLogin {
            device_id: arkret_sdk::DeviceId::new("ak:device:019f0000-0000-7000-8000-000000000001")
                .unwrap(),
            dpop_jkt: None,
            anonymous_storage_incarnation: Some(incarnation.clone()),
        })
    });
    // The public intent is durable but its writer never ran: the production
    // boot path must finish this exact repair without clearing an accepted cut.
    LocalStateStore::prepare_account_records(vec![ANONYMOUS_ACCOUNT_NAMESPACE.into()]).await?;
    let mut fresh = LocalStateStore::default();
    anyhow::ensure!(
        fresh.load() == ClientLocalState::default(),
        "repair revived unreadable old scratch state"
    );
    fresh.save_sync_cursor("fresh-anonymous");
    fresh.begin_durable_flush()?.wait().await?;
    LocalStateStore::prepare_account_records(vec![ANONYMOUS_ACCOUNT_NAMESPACE.into()]).await?;
    anyhow::ensure!(
        LocalStateStore::default().load().sync_cursor.as_deref() == Some("fresh-anonymous"),
        "replayed repair erased its new recovery material"
    );
    let diagnostic_key = format!(
        "{}quarantine/{incarnation}/root",
        prefix(ANONYMOUS_ACCOUNT_NAMESPACE)
    );
    let diagnostic: Value = serde_json::from_slice(
        &backend
            .get(&diagnostic_key)
            .await?
            .context("repair did not preserve unreadable root")?,
    )?;
    anyhow::ensure!(
        diagnostic["ciphertext"] == hex::encode(raw),
        "repair changed original diagnostic bytes"
    );
    let old_record = &old.records[&vec!["sync_cursor".into()]];
    anyhow::ensure!(
        backend
            .get(&chunk_key(&old_data, &old_record.blob, 0))
            .await?
            .is_some(),
        "repair destroyed quarantined private records"
    );
    Ok(())
}
