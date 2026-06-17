//! Seal-view defaults, frontier selection, bottom-cell conflict resolution,
//! sync-body parsing, and cross-realm aggregation.

use super::*;

#[test]
fn seal_view_default_returns_empty_bytes_sentinel() {
    let path = temp_state_path("seal-default");
    let store = LocalStateStore::with_path(path);
    let view = store.seal_view_for_realm("ck:realm:demo");
    assert!(view.frontier.is_empty());
    assert!(view.leaves.is_empty());
    assert!(view.state_root.is_none());
    assert_eq!(view.move_seal_ref(), LocalSealView::EMPTY_ANCHOR_REF);
    assert_eq!(
        store.seal_ref_for_realm_move("ck:realm:demo"),
        LocalSealView::EMPTY_ANCHOR_REF
    );
}

#[test]
fn seal_view_set_persists_and_picks_lex_min_frontier() {
    let path = temp_state_path("seal-set");
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.set_realm_seal_view(
            "ck:realm:demo",
            LocalSealView {
                frontier: vec![
                    "ck:seal:sha256:bbb".to_owned(),
                    "ck:seal:sha256:aaa".to_owned(),
                ],
                leaves: vec!["sha256:lf1".to_owned()],
                state_root: Some("ck:state:sha256:abc".to_owned()),
                bottom_cells: BTreeMap::new(),
                mls_epoch: None,
                covered_seals: None,
                covered_seals_lag: None,
                key_schedule_hash: None,
            },
        );
    }
    let reader = LocalStateStore::with_path(path);
    let view = reader.seal_view_for_realm("ck:realm:demo");
    assert_eq!(view.frontier.len(), 2);
    assert_eq!(view.leaves.len(), 1);
    assert_eq!(view.state_root.as_deref(), Some("ck:state:sha256:abc"));
    assert_eq!(view.move_seal_ref(), "ck:seal:sha256:aaa");
    assert_eq!(
        reader.seal_ref_for_realm_move("ck:realm:demo"),
        "ck:seal:sha256:aaa"
    );
}

#[test]
fn seal_view_bottom_cells_signal_conflict() {
    let mut view = LocalSealView::default();
    assert!(!view.has_bottom_cells());
    view.bottom_cells.insert(
        "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned(),
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
    let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ck:event:joined".to_owned(),
                    value: serde_json::json!({"membership": "join"}),
                },
                BottomCellHead {
                    move_id: "ck:event:banned".to_owned(),
                    value: serde_json::json!({"membership": "ban", "reason": "abuse"}),
                },
            ],
        },
    );
    let (head_a, head_b, winner) = view.safer_winner_for(&cell).expect("ban beats join");
    assert_eq!(head_a, "ck:event:joined");
    assert_eq!(head_b, "ck:event:banned");
    assert_eq!(
        winner.get("membership").and_then(|v| v.as_str()),
        Some("ban")
    );
}

#[test]
fn safer_winner_for_capability_grant_prefers_revoked_over_active() {
    let mut view = LocalSealView::default();
    let cell = "ck:cell:ck.component.capability.grant.v1:ck.grant.01".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ck:event:granted".to_owned(),
                    value: serde_json::json!({"status": "active"}),
                },
                BottomCellHead {
                    move_id: "ck:event:revoked".to_owned(),
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
    let cell = "ck:cell:ck.component.test.unknown.v1:ck:realm:demo".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ck:event:a".to_owned(),
                    value: serde_json::json!({"title": "alpha"}),
                },
                BottomCellHead {
                    move_id: "ck:event:b".to_owned(),
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
    let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ck:event:ban-a".to_owned(),
                    value: serde_json::json!({"membership": "ban", "reason": "spam"}),
                },
                BottomCellHead {
                    move_id: "ck:event:ban-b".to_owned(),
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
    let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
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
            "frontier": ["ck:seal:sha256:aaa", "ck:seal:sha256:bbb"],
            "leaves":   ["sha256:lf1"],
            "state_root": "ck:state:sha256:abc",
            "cells": {
                "ck:cell:ck.component.member.state.v1:did:web:alice": {
                    "bottom": "expose",
                    "heads": [
                        {
                            "move_id": "ck:event:joined",
                            "value": {"membership": "join"}
                        },
                        {
                            "move_id": "ck:event:banned",
                            "value": {"membership": "ban", "reason": "abuse"}
                        }
                    ]
                },
                "ck:cell:ck.component.consent.grant.v1:cnt.x":         { "bottom": "reject" }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.frontier.len(), 2);
    assert_eq!(view.leaves, vec!["sha256:lf1".to_owned()]);
    assert_eq!(view.state_root.as_deref(), Some("ck:state:sha256:abc"));
    // Only `bottom=expose` cells are surfaced — `reject` cells stay
    // out of the conflict map.
    assert_eq!(view.bottom_cells.len(), 1);
    let info = view
        .bottom_cells
        .get("ck:cell:ck.component.member.state.v1:did:web:alice")
        .expect("expose cell present");
    assert_eq!(info.status, "expose");
    assert_eq!(info.heads.len(), 2);
    assert_eq!(info.heads[0].move_id, "ck:event:joined");
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
            "cell": "ck:cell:ck.component.strand.position.v1:ck:space:board:ck:strand:card",
            "status": "conflict",
            "bottom": {
                "kind": "conflict",
                "cells": [
                    "ck:cell:ck.component.strand.position.v1:ck:space:board:ck:strand:card"
                ],
                "event_ids": [
                    "ck:event:0196419b-0000-7000-8000-000000000001",
                    "ck:event:0196419b-0000-7000-8000-000000000002"
                ],
                "heads": [
                    {"list_space_id": "ck:space:list-a", "rank": "U"},
                    {"list_space_id": "ck:space:list-b", "rank": "U"}
                ]
            }
        }]
    });

    let view = LocalSealView::from_sync_body(&body);
    let info = view
        .bottom_cells
        .get("ck:cell:ck.component.strand.position.v1:ck:space:board:ck:strand:card")
        .expect("structured bottom conflict surfaced");
    assert_eq!(info.status, "conflict");
    assert_eq!(info.heads.len(), 2);
    assert_eq!(
        info.heads[0].move_id,
        "ck:event:0196419b-0000-7000-8000-000000000001"
    );
    assert_eq!(
        info.heads[1]
            .value
            .get("list_space_id")
            .and_then(|v| v.as_str()),
        Some("ck:space:list-b")
    );
}

#[test]
fn seal_view_from_sync_body_extracts_mls_epoch_and_covered_seals() {
    let body = serde_json::json!({
        "seal_view": {
            "frontier": ["ck:seal:sha256:aaa"],
            "leaves": [],
            "cells": {
                "ck:cell:ck.component.mls.epoch.v1:ck:realm:demo": {
                    "value": 7
                },
                "ck:cell:ck.component.governance.covered_seals.v1:ck:realm:demo": {
                    "register": { "value": "ck:state:sha256:abcd" }
                }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.mls_epoch, Some(7));
    assert_eq!(view.covered_seals.as_deref(), Some("ck:state:sha256:abcd"));
}

#[test]
fn seal_view_mls_epoch_supports_object_value_with_epoch_field() {
    // Some soland builds emit the MLS epoch cell as `{ "value": { "epoch": N } }`
    // (typed view) instead of a bare integer. Both shapes need to round-trip.
    let body = serde_json::json!({
        "seal_view": {
            "frontier": [],
            "cells": {
                "ck:cell:ck.component.mls.epoch.v1:ck:realm:demo": {
                    "value": { "epoch": 42, "members": 3 }
                }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.mls_epoch, Some(42));
}

#[test]
fn seal_view_from_sync_body_extracts_covered_seals_lag() {
    let body = serde_json::json!({
        "seal_view": {
            "frontier": ["ck:seal:sha256:aaa"],
            "leaves": [],
            "covered_seals_lag": 12,
            "cells": {}
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.covered_seals_lag, Some(12));
    // default threshold is 5 -> 12 > 5
    assert!(view.covered_seals_lag_above(5));
    assert!(!view.covered_seals_lag_above(20));
}

#[test]
fn seal_view_lag_above_returns_false_when_lag_unknown() {
    let view = LocalSealView::default();
    assert!(!view.covered_seals_lag_above(5));
    assert!(!view.covered_seals_lag_above(0));
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
        "ck:realm:one",
        LocalSealView {
            frontier: vec!["ck:seal:sha256:one".to_owned()],
            ..LocalSealView::default()
        },
    );
    store.set_realm_seal_view(
        "ck:realm:two",
        LocalSealView {
            frontier: vec!["ck:seal:sha256:two".to_owned()],
            ..LocalSealView::default()
        },
    );
    let all = store.seal_views();
    assert_eq!(all.len(), 2);
    assert!(all.contains_key("ck:realm:one"));
    assert!(all.contains_key("ck:realm:two"));
}
