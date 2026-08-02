//! Seal-view defaults, frontier selection, bottom-cell conflict resolution,
//! sync-body parsing, and cross-realm aggregation.

use super::*;

#[test]
fn seal_view_default_returns_empty_bytes_sentinel() {
    let path = temp_state_path("seal-default");
    let store = LocalStateStore::with_path(path);
    let view = store.seal_view_for_realm("ak:realm:demo");
    assert!(view.frontier.is_empty());
    assert!(view.leaves.is_empty());
    assert!(view.state_root.is_none());
    assert_eq!(view.move_seal_ref(), LocalSealView::EMPTY_ANCHOR_REF);
    assert_eq!(
        store.seal_ref_for_realm_move("ak:realm:demo"),
        LocalSealView::EMPTY_ANCHOR_REF
    );
}

#[test]
fn seal_view_set_persists_and_picks_lex_min_frontier() {
    let path = temp_state_path("seal-set");
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.set_realm_seal_view(
            "ak:realm:demo",
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
    let view = reader.seal_view_for_realm("ak:realm:demo");
    assert_eq!(view.frontier.len(), 2);
    assert_eq!(view.leaves.len(), 1);
    assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:abc"));
    assert_eq!(view.move_seal_ref(), "ak:seal:sha256:aaa");
    assert_eq!(
        reader.seal_ref_for_realm_move("ak:realm:demo"),
        "ak:seal:sha256:aaa"
    );
}

#[test]
fn seal_view_bottom_cells_signal_conflict() {
    let mut view = LocalSealView::default();
    assert!(!view.has_bottom_cells());
    view.bottom_cells.insert(
        "ak:cell:ak.component.member.state.v1:did:web:alice".to_owned(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![],
        },
    );
    assert!(view.has_bottom_cells());
}

#[test]
fn safer_winner_for_member_state_prefers_ban_over_join() {
    let mut view = LocalSealView::default();
    let cell = "ak:cell:ak.component.member.state.v1:did:web:alice".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ak:event:joined".to_owned(),
                    value: serde_json::json!({"membership": "join"}),
                },
                BottomCellHead {
                    move_id: "ak:event:banned".to_owned(),
                    value: serde_json::json!({"membership": "ban", "reason": "abuse"}),
                },
            ],
        },
    );
    let (head_a, head_b, winner) = view.safer_winner_for(&cell).expect("ban beats join");
    assert_eq!(head_a, "ak:event:joined");
    assert_eq!(head_b, "ak:event:banned");
    assert_eq!(
        winner.get("membership").and_then(|v| v.as_str()),
        Some("ban")
    );
}

#[test]
fn safer_winner_for_capability_grant_prefers_revoked_over_active() {
    let mut view = LocalSealView::default();
    let cell = "ak:cell:ak.component.capability.grant.v1:ak.grant.01".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ak:event:granted".to_owned(),
                    value: serde_json::json!({"status": "active"}),
                },
                BottomCellHead {
                    move_id: "ak:event:revoked".to_owned(),
                    value: serde_json::json!({"status": "revoked"}),
                },
            ],
        },
    );
    let (_, _, winner) = view.safer_winner_for(&cell).expect("revoked beats active");
    assert_eq!(
        winner.get("status").and_then(|v| v.as_str()),
        Some("revoked")
    );
}

#[test]
fn safer_winner_for_unknown_cell_family_returns_none() {
    let mut view = LocalSealView::default();
    let cell = "ak:cell:ak.component.test.unknown.v1:ak:realm:demo".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ak:event:a".to_owned(),
                    value: serde_json::json!({"title": "alpha"}),
                },
                BottomCellHead {
                    move_id: "ak:event:b".to_owned(),
                    value: serde_json::json!({"title": "beta"}),
                },
            ],
        },
    );
    // No semantic safety ordering for this test-only cell family — operator
    // must pick manually.
    assert!(view.safer_winner_for(&cell).is_none());
}

#[test]
fn safer_winner_for_tied_heads_returns_none() {
    let mut view = LocalSealView::default();
    let cell = "ak:cell:ak.component.member.state.v1:did:web:alice".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ak:event:ban-a".to_owned(),
                    value: serde_json::json!({"membership": "ban", "reason": "spam"}),
                },
                BottomCellHead {
                    move_id: "ak:event:ban-b".to_owned(),
                    value: serde_json::json!({"membership": "ban", "reason": "abuse"}),
                },
            ],
        },
    );
    // Both heads tie on safety rank → no preference; operator picks.
    assert!(view.safer_winner_for(&cell).is_none());
}

#[test]
fn safer_winner_for_missing_heads_returns_none() {
    let mut view = LocalSealView::default();
    let cell = "ak:cell:ak.component.member.state.v1:did:web:alice".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![],
        },
    );
    assert!(view.safer_winner_for(&cell).is_none());
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
                            "move_id": "ak:event:joined",
                            "value": {"membership": "join"}
                        },
                        {
                            "move_id": "ak:event:banned",
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
    assert_eq!(info.heads[0].move_id, "ak:event:joined");
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
                    "ak:event:0196419b-0000-7000-8000-000000000001",
                    "ak:event:0196419b-0000-7000-8000-000000000002"
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
        "ak:event:0196419b-0000-7000-8000-000000000001"
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
        "ak:realm:one",
        LocalSealView {
            frontier: vec!["ak:seal:sha256:one".to_owned()],
            ..LocalSealView::default()
        },
    );
    store.set_realm_seal_view(
        "ak:realm:two",
        LocalSealView {
            frontier: vec!["ak:seal:sha256:two".to_owned()],
            ..LocalSealView::default()
        },
    );
    let all = store.seal_views();
    assert_eq!(all.len(), 2);
    assert!(all.contains_key("ak:realm:one"));
    assert!(all.contains_key("ak:realm:two"));
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
                    "ak:event:0196419b-0000-7000-8000-000000000001",
                    "ak:event:0196419b-0000-7000-8000-000000000002"
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
        "ak:realm:demo",
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
    store.merge_realm_seal_view_from_sync_body("ak:realm:demo", &conflict_bottoms_body(cell));

    let view = store.seal_view_for_realm("ak:realm:demo");
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
    store.merge_realm_seal_view_from_sync_body("ak:realm:demo", &conflict_bottoms_body(first));
    store.merge_realm_seal_view_from_sync_body("ak:realm:demo", &conflict_bottoms_body(second));

    let view = store.seal_view_for_realm("ak:realm:demo");
    assert!(!view.bottom_cells.contains_key(first));
    assert!(view.bottom_cells.contains_key(second));
    let _ = std::fs::remove_file(path);
}

#[test]
fn sync_body_with_seal_view_still_replaces_the_stored_view() {
    let path = temp_state_path("seal-merge-replace");
    let mut store = LocalStateStore::with_path(path.clone());
    store.set_realm_seal_view(
        "ak:realm:demo",
        LocalSealView {
            frontier: vec!["ak:seal:sha256:aaa".to_owned()],
            ..Default::default()
        },
    );
    store.merge_realm_seal_view_from_sync_body(
        "ak:realm:demo",
        &serde_json::json!({
            "seal_view": {
                "frontier": ["ak:seal:sha256:bbb"],
                "state_root": "ak:state:sha256:def"
            }
        }),
    );

    let view = store.seal_view_for_realm("ak:realm:demo");
    assert_eq!(view.frontier, vec!["ak:seal:sha256:bbb".to_owned()]);
    assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:def"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn sync_merge_keeps_the_verified_governance_proof_a_bare_set_would_evict() {
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let anchor = "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let body = conflict_bottoms_body("ak:cell:ak.component.member.state.v1:did:webvh:zfixture:a");

    let merge_path = temp_state_path("seal-merge-proof");
    let mut merged = LocalStateStore::with_path(merge_path.clone());
    crate::mls::governance_proof::seed_test_governance_proof(
        &mut merged,
        realm,
        None,
        "dGVzdC1tbHM",
        0,
        1,
    );
    let request =
        crate::mls::governance_proof::proof_request(&merged, realm, None, "dGVzdC1tbHM", 0, 1)
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
            .cached_mls_governance_proof(&request, chrono::Utc::now())
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
        "dGVzdC1tbHM",
        0,
        1,
    );
    evicted.set_realm_seal_view(realm, LocalSealView::from_sync_body(&body));
    assert!(
        evicted
            .cached_mls_governance_proof(&request, chrono::Utc::now())
            .expect("cache read")
            .is_none()
    );

    let _ = std::fs::remove_file(merge_path);
    let _ = std::fs::remove_file(evict_path);
}
