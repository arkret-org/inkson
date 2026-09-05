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
fn account_snapshot_refresh_preserves_local_realm_profile_overlay() {
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
    store.save_realm_tree_projection(realm_id, json!({"summary": {"title": "stale"}}));

    assert_eq!(
        store.load().realm_tree_projections[realm_id]["_inkson_realm_profile_payload"]["title"],
        "current"
    );
}

#[test]
fn account_snapshot_refresh_preserves_pre_genesis_mls_binding_selectors() {
    let path = temp_state_path("pre-genesis-mls-binding-refresh");
    let mut store = LocalStateStore::with_path(path);
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";

    store.save_realm_tree_projection(
        realm_id,
        json!({
            "summary": {"title": "Encrypted"},
            "content_scheme": "mls_exporter_aead_v1",
            "durability_policy": {"kind": "rhrk_v1"}
        }),
    );
    store.save_realm_tree_projection(
        realm_id,
        json!({"summary": {"title": "Encrypted", "encryption_profile": "mls_rfc9420"}}),
    );

    let projection = &store.load().realm_tree_projections[realm_id];
    assert_eq!(projection["content_scheme"], "mls_exporter_aead_v1");
    assert_eq!(projection["durability_policy"]["kind"], "rhrk_v1");
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
fn mls_encrypted_projection_detects_epoch_pause_scope() {
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
    assert!(store.realm_projection_is_mls_encrypted(realm));

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
fn mls_encrypted_projection_reads_canonical_realm_create_state_event() {
    let path = temp_state_path("mls-encrypted-state-event-projection");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:AbL5fawW_ixBPm33UQ3u2DB4FgKEE52qRcPacwGPz9Hh";
    store.save_realm_tree_projection(
        realm,
        json!({
            "summary": {"joined_member_count": 2},
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {
                    "encryption_profile": "mls_rfc9420",
                    "history_access": "all_history_for_current_members"
                }}
            }]}
        }),
    );

    assert!(store.realm_projection_is_mls_encrypted(realm));
}

#[test]
fn minimal_metadata_projection_detected_from_genesis_schema_refs() {
    // SEC-08 — only the create-locked structural role in `schema_refs[]` is
    // authoritative; generic profile arrays are rejected as Realm state.
    let path = temp_state_path("minimal-metadata-projection");
    let mut store = LocalStateStore::with_path(path);

    let top = "ak:realm:Af7kHhjQt9bXM9MVmV6uu7VNZY1P_sjoIUGS2rxLV8Qt";
    store.save_realm_tree_projection(
        top.to_owned(),
        json!({ "schema_refs": [arkret_sdk::ProfileId::MLS_MINIMAL_METADATA_REALM_V1] }),
    );
    assert!(store.realm_projection_is_minimal_metadata(top));

    let nested = "ak:realm:Ad0zM3xkilGkLE8K9IPZrZvbQzit2do46Wb6ECOCaX6k";
    store.save_realm_tree_projection(
        nested.to_owned(),
        json!({
            "summary": {
                "schema_refs": [
                    "ak.profile.core.v1",
                    arkret_sdk::ProfileId::MLS_MINIMAL_METADATA_REALM_V1
                ]
            }
        }),
    );
    assert!(store.realm_projection_is_minimal_metadata(nested));

    let plain = "ak:realm:AUsIM7jMWF-QEkZ3Fd8dVqgxiIcM5iASgTtudL5PCcGL";
    store.save_realm_tree_projection(
        plain.to_owned(),
        json!({ "schema_refs": ["ak.profile.core.v1"] }),
    );
    assert!(!store.realm_projection_is_minimal_metadata(plain));

    let retired = "ak:realm:AUKBRx5s1e-cYkHAftYCs36bgPmoYQVWDau5uOOyrgzF";
    store.save_realm_tree_projection(
        retired.to_owned(),
        json!({ "active_profiles": [arkret_sdk::ProfileId::MLS_MINIMAL_METADATA_REALM_V1] }),
    );
    assert!(!store.realm_projection_is_minimal_metadata(retired));

    // Unknown Realm (no projection) ⇒ treated as non-minimal.
    assert!(!store.realm_projection_is_minimal_metadata(
        "ak:realm:AcN-V6vbQWbYV_LFa1cc3Vo7blS7mIpHd7DQDo9mePUM"
    ));
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
/// the ruling recorded in
/// `review/spec-done/2026-09-04-2153-member-roster-subject-carrier-prose-and-schema-disagree.md`.
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

/// `authority_binding.witness_attestations[]` is a closed
/// `{witness_id, proof}` object, and the proof commits to the SDK's canonical
/// witness projection — a separate object family from the manifest signature.
/// Nothing here is assembled locally.
#[test]
fn witness_attestations_are_built_from_the_sdk_witness_projection() {
    let items = vec![arkret_sdk::SnapshotMaterializedItem::object(
        "realm".to_owned(),
        "ak:realm:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml".to_owned(),
        json!({ "title": "Witnessed Realm" }),
        snapshot_event_id("0000000000a2"),
    )];
    let (mut manifest, _chunks) = snapshot_manifest_for_items(items);
    // A non-witness-quorum manifest carries no attestations at all.
    manifest.validate_witness_attestation_shape().unwrap();

    manifest.authority_binding.authority_kind = arkret_sdk::SnapshotAuthorityKind::WitnessQuorum;
    let attestations = ["did:web:witness-a.example", "did:web:witness-b.example"]
        .into_iter()
        .map(|did| {
            let witness_id = crate::mls_api_helpers::principal_core_id(did).unwrap();
            let digest = manifest.witness_attestation_digest(&witness_id).unwrap();
            arkret_sdk::snapshot::SnapshotWitnessAttestation {
                witness_id,
                proof: arkret_sdk::DetachedJwsProof::ed25519(
                    arkret_sdk::DidUrl::new(format!("{did}#witness")).unwrap(),
                    digest,
                    manifest.created_at,
                    "header..signature".to_owned(),
                ),
            }
        })
        .collect();
    manifest.authority_binding.witness_attestations = attestations;
    manifest.validate_witness_attestation_shape().unwrap();

    // The witness transcript excludes every signature, so it is not the
    // manifest signing payload.
    assert_ne!(
        manifest.authority_binding.witness_attestations[0]
            .proof
            .payload_digest,
        manifest.expected_signature_digest().unwrap()
    );

    // Order is a schema condition, never normalized away.
    manifest.authority_binding.witness_attestations.reverse();
    let error = manifest.validate_witness_attestation_shape().unwrap_err();
    assert_eq!(
        error.code,
        arkret_sdk::SnapshotValidationCode::SchemaViolation
    );
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
        store.set_realm_seal_view(id, LocalSealView::default());
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
    assert!(!state.seal_views.contains_key(DROP_A));
    assert!(state.seal_views.contains_key(KEEP));
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
        store.set_realm_seal_view(id, LocalSealView::default());
    }

    store.forget_realm_tree_projection("ak:space:gone");

    let state = store.load();
    assert!(!state.realm_tree_projections.contains_key("ak:space:gone"));
    assert!(state.realm_tree_projections.contains_key("ak:space:stay"));
}
