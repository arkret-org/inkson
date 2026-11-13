use std::time::Instant;

use super::*;

#[test]
fn account_cursor_transaction_is_bounded_at_realm_and_member_scale() {
    let mut expected: Option<(usize, usize)> = None;
    for realm_count in [1, 100, 1000] {
        let path = temp_state_path(&format!("account-items-{realm_count}"));
        let mut store = LocalStateStore::with_path(&path);
        let mut state = ClientLocalState::default();
        for index in 0u64..realm_count as u64 {
            let digest = arkret_sdk::canonical::sha256_bytes(index.to_le_bytes());
            let event = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, digest);
            let realm = arkret_sdk::RealmId::from_event_id(&event);
            let stream = arkret_sdk::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            };
            let key = realm.to_string();
            state.realm_tree_projections.insert(
                key.clone(),
                serde_json::json!({"title":format!("Realm {index}"),"summary":"x".repeat(256)}),
            );
            state
                .member_identity_events
                .entry(key.clone())
                .or_default()
                .insert(
                    format!("actor-{index}"),
                    vec![serde_json::json!({"payload":"y".repeat(128)})].into(),
                );
            let envelope = garth::mls::checkpoint::encrypt_state(
                &key,
                "group",
                1,
                b"storage checkpoint",
                "secret",
                &index.to_le_bytes(),
            );
            state.mls_local_checkpoints.insert(key.clone(), envelope);
            state.realm_authority_basis.insert(
                key,
                PersistedRealmAuthorityBasis {
                    realm_id: realm,
                    current_service_id: crate::test_support::core_id("did:web:station.example"),
                    current_generation: 0,
                    genesis_ref: arkret_sdk::CommittedEventRef {
                        event_id: event,
                        commit_id: arkret_sdk::RealmCommitId::from_digest(digest),
                        stream_ref: stream,
                        stream_position: 0,
                    },
                    last_authority_change_ref: None,
                    validated_at: "2026-10-15T00:00:00Z".parse().unwrap(),
                },
            );
        }
        store.save(state);
        assert!(
            store.persist_error().is_none(),
            "{:?}",
            store.persist_error()
        );
        let old = store
            .account_checkpoints
            .lock()
            .unwrap()
            .get(ANONYMOUS_ACCOUNT_NAMESPACE)
            .unwrap()
            .checkpoint
            .clone();
        let start = Instant::now();
        let mut updated = store.load();
        let load_us = start.elapsed().as_micros();
        assert!(
            old.state
                .realm_tree_projections
                .ptr_eq(&updated.realm_tree_projections)
        );
        assert!(old.state.member_identity_events == updated.member_identity_events);
        let cloned = store.clone();
        assert!(
            cloned
                .cached
                .realm_tree_projections
                .ptr_eq(&store.cached.realm_tree_projections)
        );
        assert!(
            cloned
                .cached
                .member_identity_events
                .ptr_eq(&store.cached.member_identity_events)
        );
        updated.sync_cursor = Some("next-page".into());
        let plan = account_store::plan(ANONYMOUS_ACCOUNT_NAMESPACE, &old, updated.clone()).unwrap();
        let writes = (
            plan.writes.len(),
            plan.writes
                .iter()
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>(),
        );
        assert_eq!(
            writes.0, 3,
            "one cursor record, one bounded chunk and one root"
        );
        if let Some(expected) = expected {
            assert_eq!(writes.0, expected.0);
            assert!(
                writes.1 <= expected.1 + 20 && writes.1 <= 1024,
                "cursor transaction grew with unrelated Realms"
            );
        } else {
            expected = Some(writes);
        }
        let start = Instant::now();
        store.save(updated);
        let write_us = start.elapsed().as_micros();
        assert!(
            store.persist_error().is_none(),
            "{:?}",
            store.persist_error()
        );
        let start = Instant::now();
        let reopened = LocalStateStore::with_path(&path).load();
        let reopen_us = start.elapsed().as_micros();
        assert_eq!(reopened.sync_cursor.as_deref(), Some("next-page"));
        assert_eq!(reopened.realm_tree_projections.len(), realm_count);
        assert_eq!(reopened.member_identity_events.len(), realm_count);
        assert_eq!(reopened.mls_local_checkpoints.len(), realm_count);
        assert_eq!(reopened.realm_authority_basis.len(), realm_count);
        assert_eq!(reopened, store.load());
        eprintln!(
            "account_items realms={realm_count} cursor_records={} cursor_payload_bytes={} cached_load_us={load_us} cursor_write_us={write_us} cold_read_us={reopen_us}",
            writes.0, writes.1
        );
    }
}
