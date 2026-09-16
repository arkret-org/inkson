//! Seal-view defaults, unique confirmation-head handling, sync-body parsing,
//! and cross-realm aggregation.

use super::*;

#[test]
fn seal_view_default_has_no_fabricated_basis() {
    let path = temp_state_path("seal-default");
    let store = LocalStateStore::with_path(path);
    let view = store.seal_view_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE");
    assert!(view.frontier.is_empty());
    assert!(view.leaves.is_empty());
    assert!(view.state_root.is_none());
    assert_eq!(
        store.confirmed_seal_ref_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"),
        None
    );
}

#[test]
fn seal_view_set_persists_the_unique_confirmed_head() {
    let path = temp_state_path("seal-set");
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.set_realm_seal_view(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            LocalSealView {
                frontier: vec!["ak:seal:sha256:aaa".to_owned()],
                leaves: vec!["sha256:lf1".to_owned()],
                state_root: Some("ak:state:sha256:abc".to_owned()),
                mls_epoch: None,
                key_schedule_hash: None,
            },
        );
    }
    let reader = LocalStateStore::with_path(path);
    let view = reader.seal_view_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE");
    assert_eq!(view.frontier.len(), 1);
    assert_eq!(view.leaves.len(), 1);
    assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:abc"));
    assert_eq!(
        reader
            .confirmed_seal_ref_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"),
        Some("ak:seal:sha256:aaa".to_owned())
    );
}

#[test]
fn seal_views_aggregates_across_realms() {
    let path = temp_state_path("seal-aggregate");
    let mut store = LocalStateStore::with_path(path);
    store.set_realm_seal_view(
        "ak:realm:AK-Rc_DsPN2knFWIKRvAmWByCvIYJdY04PayD4tgemJU",
        LocalSealView {
            frontier: vec!["ak:seal:sha256:one".to_owned()],
            ..LocalSealView::default()
        },
    );
    store.set_realm_seal_view(
        "ak:realm:AYEtqzCqAMSJ8wu7cLsSqdfgYsjlT48aGFiztQ6zDge8",
        LocalSealView {
            frontier: vec!["ak:seal:sha256:two".to_owned()],
            ..LocalSealView::default()
        },
    );
    let all = store.seal_views();
    assert_eq!(all.len(), 2);
    assert!(all.contains_key("ak:realm:AK-Rc_DsPN2knFWIKRvAmWByCvIYJdY04PayD4tgemJU"));
    assert!(all.contains_key("ak:realm:AYEtqzCqAMSJ8wu7cLsSqdfgYsjlT48aGFiztQ6zDge8"));
}

// ── sync-body merge (client-sync.md publishes no Seal view on the Realm delta)

#[test]
fn sync_body_without_seal_view_preserves_the_authoritative_frontier() {
    let path = temp_state_path("seal-merge-preserve");
    let mut store = LocalStateStore::with_path(path.clone());
    store.set_realm_seal_view(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        LocalSealView {
            frontier: vec!["ak:seal:sha256:aaa".to_owned()],
            state_root: Some("ak:state:sha256:abc".to_owned()),
            mls_epoch: Some(3),
            ..Default::default()
        },
    );

    // `RealmSyncEntry` has no `seal_view` field, so every real sync body looks
    // like this. It says nothing about the frontier and must not clear it.
    store.merge_realm_seal_view_from_sync_body(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &serde_json::json!({"current":{"entries":[]}}),
    );

    let view = store.seal_view_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE");
    assert_eq!(view.frontier, vec!["ak:seal:sha256:aaa".to_owned()]);
    assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:abc"));
    assert_eq!(view.mls_epoch, Some(3));
    let _ = std::fs::remove_file(path);
}

#[test]
fn sync_body_with_seal_view_still_replaces_the_stored_view() {
    let path = temp_state_path("seal-merge-replace");
    let mut store = LocalStateStore::with_path(path.clone());
    store.set_realm_seal_view(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        LocalSealView {
            frontier: vec!["ak:seal:sha256:aaa".to_owned()],
            ..Default::default()
        },
    );
    store.merge_realm_seal_view_from_sync_body(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &serde_json::json!({
            "seal_view": {
                "frontier": ["ak:seal:sha256:bbb"],
                "state_root": "ak:state:sha256:def"
            }
        }),
    );

    let view = store.seal_view_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE");
    assert_eq!(view.frontier, vec!["ak:seal:sha256:bbb".to_owned()]);
    assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:def"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn sync_merge_keeps_the_verified_governance_proof_a_bare_set_would_evict() {
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mls_group_id = arkret_sdk::base64url_encode(realm.as_bytes());
    let anchor = "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let body = serde_json::json!({"current":{"entries":[]}});

    let merge_path = temp_state_path("seal-merge-proof");
    let mut merged = LocalStateStore::with_path(merge_path.clone());
    crate::mls::governance_proof::seed_test_governance_result(
        &mut merged,
        realm,
        None,
        &mls_group_id,
        0,
        1,
    );
    let request = crate::mls::governance_proof::frontier_request(
        &merged,
        realm,
        None,
        &mls_group_id,
        0,
        1,
        crate::mls::governance_proof::seed_test_security_frontier_leaves(),
    )
    .expect("proof request");
    merged.set_realm_seal_view(
        realm,
        LocalSealView {
            frontier: vec![anchor.to_owned()],
            ..Default::default()
        },
    );
    merged.merge_realm_seal_view_from_sync_body(realm, &body);
    assert!(
        merged
            .cached_mls_governance_result_entry(&request, chrono::Utc::now())
            .expect("cache read")
            .is_some(),
        "a sync body carrying no Seal view must not evict a verified proof",
    );

    // Contrast: the pre-fix behaviour — replacing the view with the empty one
    // derived from the same body — drops the proof, which is what left every
    // later encrypted write with no verified binding.
    let evict_path = temp_state_path("seal-evict-proof");
    let mut evicted = LocalStateStore::with_path(evict_path.clone());
    crate::mls::governance_proof::seed_test_governance_result(
        &mut evicted,
        realm,
        None,
        &mls_group_id,
        0,
        1,
    );
    evicted.set_realm_seal_view(realm, LocalSealView::from_sync_body(&body));
    assert!(
        evicted
            .cached_mls_governance_result_entry(&request, chrono::Utc::now())
            .expect("cache read")
            .is_none()
    );

    let _ = std::fs::remove_file(merge_path);
    let _ = std::fs::remove_file(evict_path);
}
