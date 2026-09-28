use std::time::Instant;

use super::*;

#[test]
fn account_blob_cursor_write_amplification_at_realm_scale() {
    for realm_count in [1, 100, 1000] {
        let path = temp_state_path(&format!("account-blob-{realm_count}"));
        let mut store = LocalStateStore::with_path(&path);
        let mut state = ClientLocalState::default();
        for index in 0..realm_count {
            let realm = format!("ak:realm:{index:08}");
            state.realm_tree_projections.insert(
                realm.clone(),
                serde_json::json!({"title": format!("Realm {index}"), "summary": "x".repeat(256)}),
            );
            state.member_identity_events.insert(
                realm,
                BTreeMap::from([(
                    format!("actor-{index}"),
                    vec![serde_json::json!({"payload": "y".repeat(128)})],
                )]),
            );
        }
        let tree_bytes = serde_json::to_vec(&state.realm_tree_projections)
            .unwrap()
            .len();
        let identity_bytes = serde_json::to_vec(&state.member_identity_events)
            .unwrap()
            .len();
        store.save(state);
        assert!(store.persist_error().is_none());

        let account_path = store.account_state_path(ANONYMOUS_ACCOUNT_NAMESPACE);
        let before = fs::metadata(&account_path).unwrap().len();
        let load_started = Instant::now();
        let mut updated = store.load();
        let load_elapsed = load_started.elapsed();
        updated.sync_cursor = Some("next-page".to_owned());
        let write_started = Instant::now();
        store.save(updated);
        let write_elapsed = write_started.elapsed();
        let after = fs::metadata(&account_path).unwrap().len();
        let reopen_started = Instant::now();
        let reopened = LocalStateStore::with_path(&path).load();
        let reopen_elapsed = reopen_started.elapsed();
        assert_eq!(reopened.sync_cursor.as_deref(), Some("next-page"));
        assert_eq!(reopened.realm_tree_projections.len(), realm_count);
        assert_eq!(reopened.member_identity_events.len(), realm_count);
        assert!(after >= before);
        assert!(after as usize > tree_bytes + identity_bytes);
        eprintln!(
            "account_blob realms={realm_count} realm_tree_json={tree_bytes} member_identity_json={identity_bytes} cursor_update_file_bytes={after} cached_load_us={} cursor_write_us={} cold_read_us={}",
            load_elapsed.as_micros(),
            write_elapsed.as_micros(),
            reopen_elapsed.as_micros(),
        );
    }
}
