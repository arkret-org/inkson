//! Realm-tree projection, member-handle cache, and snapshot-apply / prune tests.

use serde_json::json;

use super::*;

#[test]
fn mls_encrypted_projection_detects_epoch_pause_scope() {
    let path = temp_state_path("mls-encrypted-projection");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:0196419b-0000-7000-8000-0000000000ee";
    store.save_realm_tree_projection(
        realm.to_owned(),
        json!({
            "schema": "ck.schema.realm.v1",
            "summary": {
                "title": "Encrypted",
                "encryption_profile": "mls_rfc9420"
            }
        }),
    );
    assert!(store.realm_projection_is_mls_encrypted(realm));

    let plain = "ck:realm:0196419b-0000-7000-8000-0000000000ef";
    store.save_realm_tree_projection(
        plain.to_owned(),
        json!({
            "schema": "ck.schema.realm.v1",
            "summary": {
                "title": "Plain",
                "encryption_profile": "none"
            }
        }),
    );
    assert!(!store.realm_projection_is_mls_encrypted(plain));
}

#[test]
fn minimal_metadata_projection_detected_from_profiles_arrays() {
    // SEC-08 — the committer reads minimal-metadata status off the cached
    // projection. Recognised under `profiles[]` / `active_profiles[]` at the
    // top level and inside the nested realm body; absent / unknown ⇒ false.
    let path = temp_state_path("minimal-metadata-projection");
    let mut store = LocalStateStore::with_path(path);

    let top = "ck:realm:0196419b-0000-7000-8000-0000000000a1";
    store.save_realm_tree_projection(
        top.to_owned(),
        json!({ "profiles": [cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
    );
    assert!(store.realm_projection_is_minimal_metadata(top));

    let nested = "ck:realm:0196419b-0000-7000-8000-0000000000a2";
    store.save_realm_tree_projection(
        nested.to_owned(),
        json!({
            "summary": {
                "active_profiles": [
                    "ck.profile.core.v1",
                    cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE
                ]
            }
        }),
    );
    assert!(store.realm_projection_is_minimal_metadata(nested));

    let plain = "ck:realm:0196419b-0000-7000-8000-0000000000a3";
    store.save_realm_tree_projection(
        plain.to_owned(),
        json!({ "profiles": ["ck.profile.core.v1"] }),
    );
    assert!(!store.realm_projection_is_minimal_metadata(plain));

    // Unknown Realm (no projection) ⇒ treated as non-minimal.
    assert!(
        !store
            .realm_projection_is_minimal_metadata("ck:realm:0196419b-0000-7000-8000-0000000000a9")
    );
}

#[test]
fn member_handle_cache_is_realm_and_digest_scoped() {
    let path = temp_state_path("member-handle-cache");
    let mut store = LocalStateStore::with_path(path);
    let subject = "did:webvh:zQmMember";
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
    store.save_member_handle_lookup(
        subject,
        Some(realm.to_owned()),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
        Some("Alice:Example.COM".to_owned()),
        1,
        Some(Utc::now()),
        Some(Utc::now() + chrono::Duration::hours(2)),
    );

    let entry = store
        .cached_member_handle_lookup(
            subject,
            Some(realm),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .expect("fresh cache entry");
    assert_eq!(entry.primary_handle.as_deref(), Some("alice:example.com"));
    assert!(
        store
            .cached_member_handle_lookup(
                subject,
                Some(realm),
                Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            )
            .is_none()
    );
    assert!(
        store
            .cached_member_handle_lookup(
                subject,
                Some("ck:realm:0196419b-0000-7000-8000-000000000002"),
                Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            )
            .is_none()
    );
}

#[test]
fn member_handle_cache_records_fresh_negative_lookup() {
    let path = temp_state_path("member-handle-negative-cache");
    let mut store = LocalStateStore::with_path(path);
    let subject = "did:webvh:zQmNoVisibleHandle";
    store.save_member_handle_lookup(
        subject,
        Some("ck:realm:0196419b-0000-7000-8000-000000000001".to_owned()),
        None,
        None,
        0,
        None,
        None,
    );

    let entry = store
        .cached_member_handle_lookup(
            subject,
            Some("ck:realm:0196419b-0000-7000-8000-000000000001"),
            None,
        )
        .expect("fresh negative entry");
    assert!(entry.primary_handle.is_none());
}

#[test]
fn apply_snapshot_chunks_imports_projection_status_and_encrypted_payload() {
    let path = temp_state_path("snapshot-apply");
    let mut store = LocalStateStore::with_path(path.clone());
    let message_id = "ck:message:01904100-0000-7000-8000-0000000000a1";
    let realm_id = "ck:realm:01904100-0000-7000-8000-0000000000aa";
    let encrypted_message = json!({
        "schema": "ck.schema.encrypted_envelope.v1",
        "scheme": "mls-rfc9420",
        "group_id": realm_id,
        "epoch": 1,
        "content_type": "application/vnd.cokret.message+json",
        "ciphertext": "AA",
        "payload_digest": format!("sha256:{}", "ab".repeat(32)),
        "key_ref": {
            "algorithm": "mls-rfc9420",
            "group_state_ref": format!("{realm_id}:1")
        }
    });
    let items = vec![
        cokret_sdk::SnapshotMaterializedItem {
            kind: "ck.schema.encrypted_envelope.v1".to_owned(),
            id: message_id.to_owned(),
            object: encrypted_message.clone(),
            source_event_id: snapshot_event_id("0000000000a1"),
        },
        cokret_sdk::SnapshotMaterializedItem {
            kind: "realm".to_owned(),
            id: realm_id.to_owned(),
            object: json!({
                "id": realm_id,
                "title": "Snapshot Realm"
            }),
            source_event_id: snapshot_event_id("0000000000a2"),
        },
    ];
    let (manifest, chunks) = snapshot_manifest_for_items(items);

    store
        .apply_snapshot_chunks(
            &manifest,
            &chunks,
            crate::snapshot::SnapshotTrustState::LowerTrust,
        )
        .unwrap();

    let loaded = store.load();
    assert_eq!(
        loaded.realm_tree_projections.get(message_id),
        Some(&encrypted_message)
    );
    let status = loaded.snapshot_sync.get(realm_id).unwrap();
    assert_eq!(status.manifest_id, manifest.id.to_string());
    assert_eq!(
        status.trust_state,
        crate::snapshot::SnapshotTrustState::LowerTrust
    );
    assert_eq!(status.source_event_ids.len(), 2);
    assert_eq!(store.pending_encrypted_count(), 1);

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.pending_encrypted_count(), 1);
    assert_eq!(
        reader.snapshot_sync_status(realm_id).unwrap().trust_state,
        crate::snapshot::SnapshotTrustState::LowerTrust
    );
}

#[test]
fn retain_realm_tree_projections_prunes_per_realm_caches() {
    let path = temp_state_path("retain-prunes");
    let mut store = LocalStateStore::with_path(path);
    // Seed three realms with overlapping per-realm caches.
    for id in ["ck:realm:keep", "ck:realm:drop-a", "ck:realm:drop-b"] {
        store.save_realm_tree_projection(id, serde_json::json!({"name": id}));
        store.save_draft(id, "draft");
        store.set_realm_seal_view(id, LocalSealView::default());
        store.set_realm_muted(id, true);
    }
    // Independently keyed records that should follow the prune.
    store.save_read_cursor(
        "did:web:tester.example",
        "device-1",
        "ck:realm:drop-a",
        None,
        "ck:event:42",
    );
    store.save_read_cursor(
        "did:web:tester.example",
        "device-1",
        "ck:realm:keep",
        None,
        "ck:event:99",
    );

    let pruned = store.retain_realm_tree_projections(|id| id == "ck:realm:keep");
    assert_eq!(pruned.len(), 2);
    assert!(pruned.contains(&"ck:realm:drop-a".to_owned()));
    assert!(pruned.contains(&"ck:realm:drop-b".to_owned()));

    let state = store.load();
    assert_eq!(state.realm_tree_projections.len(), 1);
    assert!(state.realm_tree_projections.contains_key("ck:realm:keep"));
    assert!(!state.drafts.contains_key("ck:realm:drop-a"));
    assert!(state.drafts.contains_key("ck:realm:keep"));
    assert!(!state.seal_views.contains_key("ck:realm:drop-a"));
    assert!(state.seal_views.contains_key("ck:realm:keep"));
    assert!(!state.realm_watch_levels.contains_key("ck:realm:drop-b"));
    assert!(state.realm_watch_levels.contains_key("ck:realm:keep"));
    let kept_marker_keys: Vec<&str> = state.read_cursors.keys().map(String::as_str).collect();
    assert!(
        kept_marker_keys
            .iter()
            .any(|k| k.starts_with("ck:realm:keep\n")),
        "kept realm marker should survive prune: {kept_marker_keys:?}",
    );
    assert!(
        kept_marker_keys
            .iter()
            .all(|k| !k.starts_with("ck:realm:drop-a\n")),
        "pruned realm marker should be gone: {kept_marker_keys:?}",
    );
}

#[test]
fn retain_realm_tree_projections_keeps_everything_when_all_match() {
    let path = temp_state_path("retain-all");
    let mut store = LocalStateStore::with_path(path);
    store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
    store.save_realm_tree_projection("ck:space:b", serde_json::json!({}));
    let pruned = store.retain_realm_tree_projections(|_| true);
    assert!(pruned.is_empty());
    assert_eq!(store.load().realm_tree_projections.len(), 2);
}

#[test]
fn forget_realm_tree_projection_clears_a_single_space() {
    let path = temp_state_path("forget-one");
    let mut store = LocalStateStore::with_path(path);
    for id in ["ck:space:gone", "ck:space:stay"] {
        store.save_realm_tree_projection(id, serde_json::json!({}));
        store.save_draft(id, "draft");
        store.set_realm_seal_view(id, LocalSealView::default());
    }

    store.forget_realm_tree_projection("ck:space:gone");

    let state = store.load();
    assert!(!state.realm_tree_projections.contains_key("ck:space:gone"));
    assert!(state.realm_tree_projections.contains_key("ck:space:stay"));
    assert!(!state.drafts.contains_key("ck:space:gone"));
    assert!(state.drafts.contains_key("ck:space:stay"));
}
