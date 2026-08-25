//! Seal-view defaults, frontier selection, bottom-cell conflict resolution,
//! sync-body parsing, and cross-realm aggregation.

use super::*;

#[test]
fn seal_view_default_returns_empty_bytes_sentinel() {
    let path = temp_state_path("seal-default");
    let store = LocalStateStore::with_path(path);
    let view = store.seal_view_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE");
    assert!(view.frontier.is_empty());
    assert!(view.leaves.is_empty());
    assert!(view.state_root.is_none());
    assert_eq!(view.move_seal_ref(), LocalSealView::EMPTY_ANCHOR_REF);
    assert_eq!(
        store.seal_ref_for_realm_move("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"),
        LocalSealView::EMPTY_ANCHOR_REF
    );
}

#[test]
fn seal_view_set_persists_and_picks_lex_min_frontier() {
    let path = temp_state_path("seal-set");
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.set_realm_seal_view(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            LocalSealView {
                frontier: vec![
                    "ak:seal:sha256:bbb".to_owned(),
                    "ak:seal:sha256:aaa".to_owned(),
                ],
                leaves: vec!["sha256:lf1".to_owned()],
                state_root: Some("ak:state:sha256:abc".to_owned()),
                bottom_cells: BTreeMap::new(),
                mls_epoch: None,
                key_schedule_hash: None,
            },
        );
    }
    let reader = LocalStateStore::with_path(path);
    let view = reader.seal_view_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE");
    assert_eq!(view.frontier.len(), 2);
    assert_eq!(view.leaves.len(), 1);
    assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:abc"));
    assert_eq!(view.move_seal_ref(), "ak:seal:sha256:aaa");
    assert_eq!(
        reader.seal_ref_for_realm_move("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"),
        "ak:seal:sha256:aaa"
    );
}

#[test]
fn seal_view_from_sync_body_parses_full_payload() {
    let body = serde_json::json!({
        "seal_view": {
            "frontier": ["ak:seal:sha256:aaa", "ak:seal:sha256:bbb"],
            "leaves":   ["sha256:lf1"],
            "state_root": "ak:state:sha256:abc",
            "cells": {
                "ak:cell:ak.component.member.state.v1:did:web:alice": {
                    "bottom": "expose",
                    "heads": [
                        {
                            "move_id": "ak:event:AReE983vfLAvHBb4ZLAr1_sY_ndBL3re3FkDrsyTVSpw",
                            "value": {"membership": "join"}
                        },
                        {
                            "move_id": "ak:event:AWXcctzU-Daf2jpmXX0bAgbadCowetMxC0YjP1qd5cF4",
                            "value": {"membership": "ban", "reason": "abuse"}
                        }
                    ]
                },
                "ak:cell:ak.component.consent.grant.v1:cnt.x":         { "bottom": "reject" }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.frontier.len(), 2);
    assert_eq!(view.leaves, vec!["sha256:lf1".to_owned()]);
    assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:abc"));
    // Only `bottom=expose` cells are surfaced — `reject` cells stay
    // out of the conflict map.
    assert_eq!(view.bottom_cells.len(), 1);
    let info = view
        .bottom_cells
        .get("ak:cell:ak.component.member.state.v1:did:web:alice")
        .expect("expose cell present");
    assert_eq!(info.status, "expose");
    assert_eq!(info.heads.len(), 2);
    assert_eq!(
        info.heads[0].move_id,
        "ak:event:AReE983vfLAvHBb4ZLAr1_sY_ndBL3re3FkDrsyTVSpw"
    );
    assert_eq!(
        info.heads[1]
            .value
            .get("membership")
            .and_then(|v| v.as_str()),
        Some("ban")
    );
}

#[test]
fn seal_view_from_sync_body_parses_structured_bottoms() {
    let body = serde_json::json!({
        "bottoms": [{
            "cell": "ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:card",
            "status": "conflict",
            "bottom": {
                "kind": "conflict",
                "cells": [
                    "ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:card"
                ],
                "event_ids": [
                    "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"
                ],
                "heads": [
                    {"list_space_id": "ak:space:list-a", "rank": "U"},
                    {"list_space_id": "ak:space:list-b", "rank": "U"}
                ]
            }
        }]
    });

    let view = LocalSealView::from_sync_body(&body);
    let info = view
        .bottom_cells
        .get("ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:card")
        .expect("structured bottom conflict surfaced");
    assert_eq!(info.status, "conflict");
    assert_eq!(info.heads.len(), 2);
    assert_eq!(
        info.heads[0].move_id,
        "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(
        info.heads[1]
            .value
            .get("list_space_id")
            .and_then(|v| v.as_str()),
        Some("ak:space:list-b")
    );
}

#[test]
fn seal_view_from_sync_body_extracts_mls_epoch() {
    let body = serde_json::json!({
        "seal_view": {
            "frontier": ["ak:seal:sha256:aaa"],
            "leaves": [],
            "cells": {
                "ak:cell:ak.component.mls.epoch.v1:ak:realm:demo": {
                    "value": 7
                }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.mls_epoch, Some(7));
}

#[test]
fn seal_view_mls_epoch_supports_object_value_with_epoch_field() {
    // Some soland builds emit the MLS epoch cell as `{ "value": { "epoch": N } }`
    // (typed view) instead of a bare integer. Both shapes need to round-trip.
    let body = serde_json::json!({
        "seal_view": {
            "frontier": [],
            "cells": {
                "ak:cell:ak.component.mls.epoch.v1:ak:realm:demo": {
                    "value": { "epoch": 42, "members": 3 }
                }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.mls_epoch, Some(42));
}

#[test]
fn seal_view_from_sync_body_missing_returns_default() {
    let body = serde_json::json!({"summary": {"summary": "hi"}});
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view, LocalSealView::default());
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

fn conflict_bottoms_body(cell: &str) -> serde_json::Value {
    serde_json::json!({
        "bottoms": [{
            "cell": cell,
            "status": "conflict",
            "bottom": {
                "kind": "conflict",
                "cells": [cell],
                "event_ids": [
                    "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"
                ]
            }
        }]
    })
}

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
    let cell = "ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:card";
    store.merge_realm_seal_view_from_sync_body(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &conflict_bottoms_body(cell),
    );

    let view = store.seal_view_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE");
    assert_eq!(view.frontier, vec!["ak:seal:sha256:aaa".to_owned()]);
    assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:abc"));
    assert_eq!(view.mls_epoch, Some(3));
    assert_eq!(view.move_seal_ref(), "ak:seal:sha256:aaa");
    // The projection-only bottoms are still refreshed from the body.
    assert!(view.bottom_cells.contains_key(cell));
    let _ = std::fs::remove_file(path);
}

#[test]
fn sync_body_bottoms_do_not_accumulate_across_windows() {
    let path = temp_state_path("seal-merge-bottoms");
    let mut store = LocalStateStore::with_path(path.clone());
    let first = "ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:first";
    let second = "ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:second";
    store.merge_realm_seal_view_from_sync_body(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &conflict_bottoms_body(first),
    );
    store.merge_realm_seal_view_from_sync_body(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &conflict_bottoms_body(second),
    );

    let view = store.seal_view_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE");
    assert!(!view.bottom_cells.contains_key(first));
    assert!(view.bottom_cells.contains_key(second));
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
    let body = conflict_bottoms_body("ak:cell:ak.component.member.state.v1:did:webvh:zfixture:a");

    let merge_path = temp_state_path("seal-merge-proof");
    let mut merged = LocalStateStore::with_path(merge_path.clone());
    crate::mls::governance_proof::seed_test_governance_proof(
        &mut merged,
        realm,
        None,
        &mls_group_id,
        0,
        1,
    );
    let request = crate::mls::governance_proof::proof_request(
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
            .cached_mls_governance_proof_entry(&request, chrono::Utc::now())
            .expect("cache read")
            .is_some(),
        "a sync body carrying no Seal view must not evict a verified proof",
    );

    // Contrast: the pre-fix behaviour — replacing the view with the empty one
    // derived from the same body — drops the proof, which is what left every
    // later encrypted write with no verified binding.
    let evict_path = temp_state_path("seal-evict-proof");
    let mut evicted = LocalStateStore::with_path(evict_path.clone());
    crate::mls::governance_proof::seed_test_governance_proof(
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
            .cached_mls_governance_proof_entry(&request, chrono::Utc::now())
            .expect("cache read")
            .is_none()
    );

    let _ = std::fs::remove_file(merge_path);
    let _ = std::fs::remove_file(evict_path);
}
