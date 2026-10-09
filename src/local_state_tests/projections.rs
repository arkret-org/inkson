//! Realm-tree projection, member-handle cache, and snapshot-apply / prune tests.

use serde_json::json;

use super::*;

#[test]
fn local_projection_commands_wait_for_the_projector() {
    let path = temp_state_path("local-projection-command-queue");
    let mut store = LocalStateStore::with_path(path);
    let operation_id = "ak:op:0196419b-0000-7000-8000-000000000001";
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";

    store.enqueue_local_projection_command(
        operation_id,
        Some(realm_id.to_owned()),
        json!({ "kind": "ak.strand.create", "write_state": "queued" }),
    );

    assert!(store.load().raw_operations.is_empty());
    assert!(store.has_pending_local_projection_commands());

    store.project_pending_local_commands();

    let state = store.load();
    assert_eq!(state.raw_operations.len(), 1);
    assert_eq!(state.raw_operations[0].operation_id, operation_id);
    assert_eq!(state.raw_operations[0].realm_id.as_deref(), Some(realm_id));
    assert!(!store.has_pending_local_projection_commands());
}

#[test]
fn account_realm_state_snapshot_refresh_preserves_local_realm_profile_overlay() {
    let path = temp_state_path("realm-profile-overlay-refresh");
    let mut store = LocalStateStore::with_path(path);
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";

    store.save_realm_tree_projection(
        realm_id,
        json!({
            "summary": {"title": "stale"},
            "_inkson_realm_profile_payload": {"title": "current"}
        }),
    );
    let existing = store.realm_tree_projection(realm_id).unwrap();
    let refreshed = garth::reconcile_realm_projection(
        Some(&existing),
        garth::RealmProjectionFrame::Incremental(&json!({"summary": {"title": "stale"}})),
    );
    store.save_realm_tree_projection(realm_id, refreshed);

    assert_eq!(
        store.load().realm_tree_projections[realm_id]["_inkson_realm_profile_payload"]["title"],
        "current"
    );
}

#[test]
fn submit_receipt_reconciles_before_local_projection_runs() {
    let path = temp_state_path("local-projection-command-fast-receipt");
    let mut store = LocalStateStore::with_path(path);
    let operation_id = "0196419b-0000-7000-8000-000000000001";
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let event_id = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    store.enqueue_local_projection_command(
        operation_id,
        Some(realm_id.to_owned()),
        json!({ "kind": "ak.strand.create", "write_state": "queued" }),
    );

    assert!(store.update_raw_operation_write_state(
        operation_id,
        "accepted",
        Some(event_id.to_owned()),
        None,
    ));
    store.project_pending_local_commands();

    let state = store.load();
    assert_eq!(state.raw_operations.len(), 1);
    assert_eq!(state.raw_operations[0].payload["write_state"], "accepted");
    assert_eq!(state.raw_operations[0].payload["event_id"], event_id);
}

#[test]
fn removed_creation_encryption_profile_does_not_activate_mls() {
    let path = temp_state_path("mls-encrypted-projection");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:AZl7EK1HY5gtksGJR-c5LC0hIz-9eSozZxy9EqwP2wTw";
    store.save_realm_tree_projection(
        realm.to_owned(),
        json!({
            "schema": "ak.schema.realm.v1",
            "summary": {
                "title": "Encrypted",
                "encryption_profile": "mls_rfc9420"
            }
        }),
    );
    assert!(!store.realm_projection_is_mls_encrypted(realm));

    let plain = "ak:realm:ARHSf2mxKS6wI8GpuAtLKy-RJVOSL_M_UEJprJwbHfO2";
    store.save_realm_tree_projection(
        plain.to_owned(),
        json!({
            "schema": "ak.schema.realm.v1",
            "summary": {
                "title": "Plain",
                "encryption_profile": "none"
            }
        }),
    );
    assert!(!store.realm_projection_is_mls_encrypted(plain));
}

#[test]
fn mls_encrypted_projection_reads_the_installed_realm_genesis_value() {
    let path = temp_state_path("mls-encrypted-genesis-current-projection");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:AbL5fawW_ixBPm33UQ3u2DB4FgKEE52qRcPacwGPz9Hh";
    assert!(!store.realm_projection_is_mls_encrypted(realm));
    store.save_realm_tree_projection(realm, json!({"summary": {"joined_member_count": 2}}));
    // A stored projection alone is not a current view.
    assert!(!store.realm_projection_is_mls_encrypted(realm));
    let group = serde_json::from_value(json!({
        "selector": {"kind": "mls_group", "scope_ref": {"kind": "realm", "realm_id": realm}},
        "source_stream_ref": {"kind": "realm", "realm_id": realm},
        "revision": {
            "commit_id": arkret_wire::RealmCommitId::from_digest([0x31; 32]),
            "stream_position": 1
        },
        "value": {
            "effective_scope": {"kind": "realm", "realm_id": realm},
            "genesis_event_ref": arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x32; 32]),
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "current_mls_commit_event_ref": arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x32; 32]),
            "epoch": 0,
            "current_key_access_revision": 0,
            "covered_key_access_revision": 0,
            "public_tree_ref": format!("ak:blob:sha256:{}", "3".repeat(64))
        }
    }))
    .unwrap();
    crate::test_support::install_current_entries(&mut store, realm, vec![group]);

    assert!(store.realm_projection_is_mls_encrypted(realm));
}

#[test]
fn retired_minimal_metadata_projection_marker_is_quarantined_after_reload() {
    const RETIRED_MARKER: &str = "ak.profile.mls.minimal_metadata_realm.v1";
    let path = temp_state_path("minimal-metadata-projection");
    let mut store = LocalStateStore::with_path(path.clone());

    let top = "ak:realm:Af7kHhjQt9bXM9MVmV6uu7VNZY1P_sjoIUGS2rxLV8Qt";
    store.save_realm_tree_projection(top.to_owned(), json!({ "schema_refs": [RETIRED_MARKER] }));
    assert!(store.realm_projection_has_retired_minimal_metadata_marker(top));

    let nested = "ak:realm:Ad0zM3xkilGkLE8K9IPZrZvbQzit2do46Wb6ECOCaX6k";
    store.save_realm_tree_projection(
        nested.to_owned(),
        json!({
            "summary": {
                "schema_refs": [
                    "ak.profile.core.v1",
                    RETIRED_MARKER
                ]
            }
        }),
    );
    assert!(store.realm_projection_has_retired_minimal_metadata_marker(nested));

    let plain = "ak:realm:AUsIM7jMWF-QEkZ3Fd8dVqgxiIcM5iASgTtudL5PCcGL";
    store.save_realm_tree_projection(
        plain.to_owned(),
        json!({ "schema_refs": ["ak.profile.core.v1"] }),
    );
    assert!(!store.realm_projection_has_retired_minimal_metadata_marker(plain));

    let retired = "ak:realm:AUKBRx5s1e-cYkHAftYCs36bgPmoYQVWDau5uOOyrgzF";
    store.save_realm_tree_projection(
        retired.to_owned(),
        json!({ "active_profiles": [RETIRED_MARKER] }),
    );
    assert!(store.realm_projection_has_retired_minimal_metadata_marker(retired));

    // Unknown Realm has no old marker; missing projection is handled by
    // ordinary governance and MLS readiness gates.
    assert!(!store.realm_projection_has_retired_minimal_metadata_marker(
        "ak:realm:AcN-V6vbQWbYV_LFa1cc3Vo7blS7mIpHd7DQDo9mePUM"
    ));
    drop(store);
    let reloaded = LocalStateStore::with_path(path);
    assert!(reloaded.realm_projection_has_retired_minimal_metadata_marker(top));
    assert!(reloaded.realm_projection_has_retired_minimal_metadata_marker(nested));
    assert!(reloaded.realm_projection_has_retired_minimal_metadata_marker(retired));
}

/// Build the exact subject account a Directory handle lookup is keyed by.
fn subject_account(principal: &str, station: &str) -> arkret_sdk::AccountId {
    test_authority_at_server(principal, station)
}

#[test]
fn member_handle_cache_is_realm_and_digest_scoped() {
    let path = temp_state_path("member-handle-cache");
    let mut store = LocalStateStore::with_path(path);
    let subject = subject_account(
        "ak:did_core:webvh:zQmMember",
        "ak:did_core:web:station-a.example",
    );
    let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    store.save_member_handle_lookup(
        &subject,
        Some(realm.to_owned()),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
        Some("Alice:Example.COM".to_owned()),
        1,
        Some(Utc::now()),
        Some(Utc::now() + chrono::Duration::hours(2)),
    );

    let entry = store
        .cached_member_handle_lookup(
            &subject,
            Some(realm),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .expect("fresh cache entry");
    assert_eq!(entry.primary_handle.as_deref(), Some("alice:example.com"));
    assert!(
        store
            .cached_member_handle_lookup(
                &subject,
                Some(realm),
                Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            )
            .is_none()
    );
    assert!(
        store
            .cached_member_handle_lookup(
                &subject,
                Some("ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"),
                Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            )
            .is_none()
    );
}

/// `discovery/discovery-directory.md` forbids merging the same principal's
/// account at another Station, so the handle cache MUST NOT answer for a
/// second Station out of the first Station's entry. This is the store half of
/// the full ActorId contract in
/// `arkret-spec/spec/v1/zh/models/common-fields.md`.
#[test]
fn member_handle_cache_never_crosses_stations_for_one_principal() {
    let path = temp_state_path("member-handle-cache-station-isolation");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let principal = "ak:did_core:webvh:zQmTwoStations";
    let at_station_a = subject_account(principal, "ak:did_core:web:station-a.example");
    let at_station_b = subject_account(principal, "ak:did_core:web:station-b.example");
    store.save_member_handle_lookup(
        &at_station_a,
        Some(realm.to_owned()),
        None,
        Some("alice:example.com".to_owned()),
        1,
        None,
        None,
    );

    assert_eq!(
        store
            .cached_member_handle_lookup(&at_station_a, Some(realm), None)
            .and_then(|entry| entry.primary_handle)
            .as_deref(),
        Some("alice:example.com")
    );
    assert!(
        store
            .cached_member_handle_lookup(&at_station_b, Some(realm), None)
            .is_none()
    );
}

#[test]
fn member_handle_cache_records_fresh_negative_lookup() {
    let path = temp_state_path("member-handle-negative-cache");
    let mut store = LocalStateStore::with_path(path);
    let subject = subject_account(
        "ak:did_core:webvh:zQmNoVisibleHandle",
        "ak:did_core:web:station-a.example",
    );
    store.save_member_handle_lookup(
        &subject,
        Some("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned()),
        None,
        None,
        0,
        None,
        None,
    );

    let entry = store
        .cached_member_handle_lookup(
            &subject,
            Some("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"),
            None,
        )
        .expect("fresh negative entry");
    assert!(entry.primary_handle.is_none());
}

#[test]
fn retain_realm_tree_projections_prunes_per_realm_caches() {
    let path = temp_state_path("retain-prunes");
    let mut store = LocalStateStore::with_path(path);
    const KEEP: &str = "ak:realm:AV56KkeEaMSR4caEiVYFp1MtJk3sQ_Zn0VETrzEWQlU3";
    const DROP_A: &str = "ak:realm:AYzH43fmsgS6dn7noiHeYxAKUUdkhaJBnOGaWvu3MlBC";
    const DROP_B: &str = "ak:realm:AQTZ4G3sx16Z36gJq1yhgC_kqqoCagJgkyhUHGh3A_EM";
    // Seed three realms with overlapping per-realm caches.
    for id in [KEEP, DROP_A, DROP_B] {
        store.save_realm_tree_projection(id, serde_json::json!({"name": id}));
        store.record_stream_head(realm_stream_head(id, 1));
        store.set_realm_muted(id, true);
    }
    // Independently keyed records that should follow the prune.
    let drop_marker = store
        .build_read_cursor_candidate(
            "did:web:tester.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            DROP_A,
            None,
            "ak:event:AUJCoQiXEV11T2wYGgq5vjXcfFcLnKQHPCp3GyzHYTDe",
        )
        .unwrap();
    store.seed_read_cursor_projection(drop_marker).unwrap();
    let keep_marker = store
        .build_read_cursor_candidate(
            "did:web:tester.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            KEEP,
            None,
            "ak:event:AXSojayi5PgA26VxFw98EsOKL49Nzr4Vvr9LPxdqgzZP",
        )
        .unwrap();
    store.seed_read_cursor_projection(keep_marker).unwrap();

    let pruned = store.retain_realm_tree_projections(|id| id == KEEP);
    assert_eq!(pruned.len(), 2);
    assert!(pruned.contains(&DROP_A.to_owned()));
    assert!(pruned.contains(&DROP_B.to_owned()));

    let state = store.load();
    assert_eq!(state.realm_tree_projections.len(), 1);
    assert!(state.realm_tree_projections.contains_key(KEEP));
    let surviving_streams: Vec<&arkret_wire::CommitStreamRef> = state
        .stream_cursors
        .values()
        .map(|head| &head.stream_ref)
        .collect();
    assert!(
        !surviving_streams
            .iter()
            .any(|stream_ref| stream_ref.realm_id().as_str() == DROP_A),
        "pruned realm stream cursor should be gone: {surviving_streams:?}",
    );
    assert!(
        surviving_streams
            .iter()
            .any(|stream_ref| stream_ref.realm_id().as_str() == KEEP),
        "kept realm stream cursor should survive: {surviving_streams:?}",
    );
    assert!(!state.realm_watch_levels.contains_key(DROP_B));
    assert!(state.realm_watch_levels.contains_key(KEEP));
    let kept_marker_keys: Vec<&str> = state.read_cursors.keys().map(String::as_str).collect();
    assert!(
        kept_marker_keys.iter().any(|k| k.starts_with(KEEP)),
        "kept realm marker should survive prune: {kept_marker_keys:?}",
    );
    assert!(
        kept_marker_keys.iter().all(|k| !k.starts_with(DROP_A)),
        "pruned realm marker should be gone: {kept_marker_keys:?}",
    );
}

#[test]
fn retain_realm_tree_projections_keeps_everything_when_all_match() {
    let path = temp_state_path("retain-all");
    let mut store = LocalStateStore::with_path(path);
    store.save_realm_tree_projection("ak:space:a", serde_json::json!({}));
    store.save_realm_tree_projection("ak:space:b", serde_json::json!({}));
    let pruned = store.retain_realm_tree_projections(|_| true);
    assert!(pruned.is_empty());
    assert_eq!(store.load().realm_tree_projections.len(), 2);
}

#[test]
fn forget_realm_tree_projection_clears_a_single_space() {
    let path = temp_state_path("forget-one");
    let mut store = LocalStateStore::with_path(path);
    for id in ["ak:space:gone", "ak:space:stay"] {
        store.save_realm_tree_projection(id, serde_json::json!({}));
    }

    store.forget_realm_tree_projection("ak:space:gone");

    let state = store.load();
    assert!(!state.realm_tree_projections.contains_key("ak:space:gone"));
    assert!(state.realm_tree_projections.contains_key("ak:space:stay"));
}
