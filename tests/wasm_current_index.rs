//! Browser regressions for the durable current index.
//!
//! The same staging, cancellation, poison and restart rules already proven
//! against real SQLite and AEAD, re-run against the real IndexedDB backend:
//! a different transaction engine owes its own evidence, and an
//! `IndexedDbSecureKeyStore` round-trip says nothing about this index.
#![cfg(target_arch = "wasm32")]

use inkson::current_index_harness::CurrentIndexHarness;
use serde_json::json;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const REALM: &str = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
const COMMIT: &str = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";

#[path = "support/search_circle.rs"]
mod search_circle;

#[wasm_bindgen_test(async)]
async fn account_scope_removal_requires_fresh_current_without_mixing_list_and_stream_positions() {
    let fixture = search_circle::Fixture::new();
    let id = authority("account-scope-removal");
    let actor = serde_json::to_string(&fixture.actor).unwrap();
    let now = search_circle::at(20).to_rfc3339();
    let snapshot = serde_json::to_string(&fixture.snapshot).unwrap();
    let expected = serde_json::to_string(&vec![fixture.message.clone()]).unwrap();
    let index = CurrentIndexHarness::open(&id, 0).await.unwrap();
    index
        .commit_snapshot(0, &fixture.frame(true), &snapshot)
        .await
        .unwrap();
    assert_eq!(index.search(&actor, &now).await.unwrap(), expected);
    index
        .commit_account_scope_change(
            1,
            &search_circle::account_scope_removal_frame(&fixture.snapshot.realm_id),
        )
        .await
        .unwrap();
    assert_eq!(index.search(&actor, &now).await.unwrap(), "[]");
    assert!(
        index
            .search_originals_present(
                &arkret_sdk::MessageId::from_event_id(&fixture.message.event.event_id).to_string()
            )
            .await
            .unwrap()
    );
    drop(index);
    let reopened = CurrentIndexHarness::open(&id, 2).await.unwrap();
    assert_eq!(reopened.search(&actor, &now).await.unwrap(), "[]");
    reopened
        .commit_account_scope_change(
            2,
            &search_circle::account_scope_rejoin_frame(&fixture.snapshot.realm_id),
        )
        .await
        .unwrap();
    assert_eq!(reopened.search(&actor, &now).await.unwrap(), "[]");
    reopened
        .commit_snapshot(3, &fixture.frame(true), &snapshot)
        .await
        .unwrap();
    assert_eq!(reopened.search(&actor, &now).await.unwrap(), expected);
}

#[wasm_bindgen_test(async)]
async fn search_retention_policy_and_validity_boundaries_survive_restart() {
    for (scenario, fixture, checks) in search_circle::policy_cases() {
        let id = authority(&format!("retention-policy-{scenario}"));
        let actor = serde_json::to_string(&fixture.actor).unwrap();
        let index = CurrentIndexHarness::open(&id, 0).await.unwrap();
        index
            .commit_snapshot(
                0,
                &fixture.frame(true),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        drop(index);
        for check in checks {
            let reopened = CurrentIndexHarness::open(&id, 1).await.unwrap();
            let now = check.now.to_rfc3339();
            let expected = if check.visible {
                vec![fixture.message.clone()]
            } else {
                vec![]
            };
            assert_eq!(
                reopened.search(&actor, &now).await.unwrap(),
                serde_json::to_string(&expected).unwrap(),
                "{scenario} {now}"
            );
            assert_eq!(
                reopened.search_recheck_at(&actor, &now).await.unwrap(),
                check.recheck_at.map(|time| time.to_rfc3339()),
                "{scenario} {now}"
            );
        }
    }
}

#[wasm_bindgen_test(async)]
async fn search_event_redaction_never_releases_cached_full_across_restart() {
    for (scenario, steps) in search_circle::event_redaction_cases() {
        let id = authority(&format!("event-redaction-{scenario}"));
        let actor = serde_json::to_string(&search_circle::Fixture::new().actor).unwrap();
        let now = search_circle::at(20).to_rfc3339();
        for (generation, step) in steps.into_iter().enumerate() {
            let index = CurrentIndexHarness::open(&id, generation as u64)
                .await
                .unwrap();
            index
                .commit_snapshot(generation as u64, &step.frame, &step.snapshot)
                .await
                .unwrap();
            let expected = serde_json::to_string(&step.expected).unwrap();
            assert_eq!(
                index.search(&actor, &now).await.unwrap(),
                expected,
                "{scenario} {generation}"
            );
            drop(index);
            let reopened = CurrentIndexHarness::open(&id, generation as u64 + 1)
                .await
                .unwrap();
            assert_eq!(
                reopened.search(&actor, &now).await.unwrap(),
                expected,
                "cold {scenario} {generation}"
            );
        }
    }
}

#[wasm_bindgen_test(async)]
async fn search_disclosure_backfill_recovers_exact_original_without_reopening_other_gates() {
    for (scenario, steps) in search_circle::disclosure_cases() {
        let id = authority(&format!("disclosure-{scenario}"));
        let actor = serde_json::to_string(&search_circle::Fixture::new().actor).unwrap();
        let now = search_circle::at(20).to_rfc3339();
        for (generation, step) in steps.into_iter().enumerate() {
            let index = CurrentIndexHarness::open(&id, generation as u64)
                .await
                .unwrap();
            index
                .commit_snapshot(generation as u64, &step.frame, &step.snapshot)
                .await
                .unwrap();
            let expected = serde_json::to_string(&step.expected).unwrap();
            assert_eq!(
                index.search(&actor, &now).await.unwrap(),
                expected,
                "{scenario} {generation}"
            );
            drop(index);
            let reopened = CurrentIndexHarness::open(&id, generation as u64 + 1)
                .await
                .unwrap();
            assert_eq!(
                reopened.search(&actor, &now).await.unwrap(),
                expected,
                "cold {scenario} {generation}"
            );
        }
    }
}

#[wasm_bindgen_test(async)]
async fn search_revision_current_advance_waits_for_exact_original_across_restart() {
    let id = authority("current-revision");
    let index = CurrentIndexHarness::open(&id, 0).await.unwrap();
    let mut fixture = search_circle::Fixture::new();
    let actor = serde_json::to_string(&fixture.actor).unwrap();
    let now = search_circle::at(20).to_rfc3339();
    index
        .commit_snapshot(
            0,
            &fixture.frame(true),
            &serde_json::to_string(&fixture.snapshot).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        index.search(&actor, &now).await.unwrap(),
        serde_json::to_string(&vec![fixture.message.clone()]).unwrap()
    );
    fixture.revise_message();
    index
        .commit_snapshot(
            1,
            &fixture.frame(false),
            &serde_json::to_string(&fixture.snapshot).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(index.search(&actor, &now).await.unwrap(), "[]");
    let revision = fixture.originals.pop().unwrap();
    index
        .commit_snapshot(
            2,
            &fixture.frame(true),
            &serde_json::to_string(&fixture.snapshot).unwrap(),
        )
        .await
        .unwrap();
    drop(index);
    let reopened = CurrentIndexHarness::open(&id, 3).await.unwrap();
    assert_eq!(reopened.search(&actor, &now).await.unwrap(), "[]");
    fixture.originals.push(revision.clone());
    reopened
        .commit_snapshot(
            3,
            &fixture.frame(true),
            &serde_json::to_string(&fixture.snapshot).unwrap(),
        )
        .await
        .unwrap();
    let expected = serde_json::to_string(&vec![fixture.message.clone(), revision]).unwrap();
    assert_eq!(reopened.search(&actor, &now).await.unwrap(), expected);
    drop(reopened);
    let recovered = CurrentIndexHarness::open(&id, 4).await.unwrap();
    assert_eq!(recovered.search(&actor, &now).await.unwrap(), expected);
}

#[wasm_bindgen_test(async)]
async fn search_revision_current_requires_exact_carrier_evidence() {
    for revised in [false, true] {
        for scenario in [
            "missing",
            "wrong_source",
            "wrong_commit",
            "wrong_position",
            "wrong_payload",
            "wrong_target",
            "older_current",
        ] {
            if !revised && scenario == "older_current" {
                continue;
            }
            let id = authority(&format!("current-revision-{revised}-{scenario}"));
            let index = CurrentIndexHarness::open(&id, 0).await.unwrap();
            let mut fixture = search_circle::Fixture::new();
            if revised {
                fixture.revise_message();
            }
            fixture.change_revision(scenario);
            let _ = index
                .commit_snapshot(
                    0,
                    &fixture.frame(true),
                    &serde_json::to_string(&fixture.snapshot).unwrap(),
                )
                .await;
            let actor = serde_json::to_string(&fixture.actor).unwrap();
            assert_eq!(
                index
                    .search(&actor, &search_circle::at(20).to_rfc3339())
                    .await
                    .unwrap(),
                "[]",
                "{revised} {scenario}"
            );
        }
    }
}

#[wasm_bindgen_test(async)]
async fn search_current_message_redaction_is_terminal_without_history_and_scrubs_candidates() {
    for scenario in [
        "redaction_only",
        "redaction_first",
        "other_message",
        "revised",
    ] {
        let id = authority(&format!("current-redaction-{scenario}"));
        let index = CurrentIndexHarness::open(&id, 0).await.unwrap();
        let mut fixture = search_circle::Fixture::new();
        if scenario == "revised" {
            fixture.revise_message();
        }
        let message = arkret_sdk::MessageId::from_event_id(&fixture.message.event.event_id);
        let actor = serde_json::to_string(&fixture.actor).unwrap();
        let now = search_circle::at(20).to_rfc3339();
        index
            .commit_snapshot(
                0,
                &fixture.frame(scenario != "redaction_first"),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        let target = if scenario == "other_message" {
            arkret_sdk::MessageId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [101; 32],
            ))
        } else {
            message.clone()
        };
        fixture.redact_message_current(target.as_str());
        index
            .commit_snapshot(
                1,
                &fixture.frame(false),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        index
            .commit_snapshot(
                2,
                &fixture.frame(true),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        let expected = if scenario == "other_message" {
            serde_json::to_string(&vec![fixture.message.clone()]).unwrap()
        } else {
            "[]".into()
        };
        assert_eq!(
            index.search(&actor, &now).await.unwrap(),
            expected,
            "{scenario}"
        );
        assert_eq!(
            index
                .search_originals_present(message.as_str())
                .await
                .unwrap(),
            scenario == "other_message",
            "retained body {scenario}"
        );
        fixture.snapshot.current_state_entries.retain(|row| {
            !matches!(
                row,
                arkret_sdk::CurrentState::Value {
                    selector: arkret_sdk::CurrentSelector::ObjectRedaction { .. },
                    ..
                }
            )
        });
        fixture.snapshot.created_at = search_circle::at(13);
        search_circle::seal(&mut fixture.snapshot);
        index
            .commit_snapshot(
                3,
                &fixture.frame(true),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        drop(index);
        let reopened = CurrentIndexHarness::open(&id, 4).await.unwrap();
        assert_eq!(
            reopened.search(&actor, &now).await.unwrap(),
            expected,
            "cold {scenario}"
        );
        assert_eq!(
            reopened
                .search_originals_present(message.as_str())
                .await
                .unwrap(),
            scenario == "other_message"
        );
    }
}

#[wasm_bindgen_test(async)]
async fn search_current_message_redaction_rejects_bad_evidence_without_publication() {
    for scenario in ["empty", "wrong_subject", "wrong_stream"] {
        let id = authority(&format!("invalid-redaction-{scenario}"));
        let index = CurrentIndexHarness::open(&id, 0).await.unwrap();
        let mut fixture = search_circle::Fixture::new();
        let actor = serde_json::to_string(&fixture.actor).unwrap();
        let now = search_circle::at(20).to_rfc3339();
        index
            .commit_snapshot(
                0,
                &fixture.frame(true),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        let target = arkret_sdk::MessageId::from_event_id(&fixture.message.event.event_id);
        fixture.redact_message_current(target.as_str());
        let arkret_sdk::CurrentState::Value {
            value,
            source_stream_ref,
            revision,
            ..
        } = fixture.snapshot.current_state_entries.last_mut().unwrap();
        match scenario {
            "empty" => value["assertions"] = json!([]),
            "wrong_subject" => {
                value["assertions"][0]["value"]["message_id"] = json!(
                    arkret_sdk::MessageId::from_event_id(&arkret_sdk::EventId::from_digest(
                        arkret_sdk::DigestSuite::Sha256,
                        [102; 32]
                    ))
                )
            }
            _ => {
                let head = &fixture.snapshot.visible_stream_heads[0];
                *source_stream_ref = head.stream_ref.clone();
                *revision = arkret_sdk::CurrentRevision {
                    commit_id: head.commit_id.clone(),
                    stream_position: head.stream_position,
                };
            }
        }
        search_circle::seal(&mut fixture.snapshot);
        assert!(
            index
                .commit_snapshot(
                    1,
                    &fixture.frame(false),
                    &serde_json::to_string(&fixture.snapshot).unwrap()
                )
                .await
                .is_err(),
            "{scenario}"
        );
        assert_eq!(
            index.search(&actor, &now).await.unwrap(),
            serde_json::to_string(&vec![fixture.message]).unwrap(),
            "old cut {scenario}"
        );
    }
}

#[wasm_bindgen_test(async)]
async fn search_circle_current_scope_survives_archive_but_not_terminal_or_missing_evidence() {
    for scenario in search_circle::SCENARIOS {
        let id = authority(&format!("search-circle-{scenario}"));
        let index = CurrentIndexHarness::open(&id, 0).await.unwrap();
        let mut fixture = search_circle::Fixture::new();
        if scenario == "wrong_source" {
            fixture.change(scenario);
        }
        let actor = serde_json::to_string(&fixture.actor).unwrap();
        let now = search_circle::at(20).to_rfc3339();
        index
            .commit_snapshot(
                0,
                &fixture.frame(true),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        let original = if scenario == "wrong_source" {
            "[]".to_owned()
        } else {
            serde_json::to_string(&vec![fixture.message.clone()]).unwrap()
        };
        assert_eq!(
            index.search(&actor, &now).await.unwrap(),
            original,
            "initial {scenario}"
        );
        if scenario == "wrong_source" {
            drop(index);
            let reopened = CurrentIndexHarness::open(&id, 1).await.unwrap();
            assert_eq!(
                reopened.search(&actor, &now).await.unwrap(),
                "[]",
                "reopened {scenario}"
            );
            continue;
        }
        fixture.change(scenario);
        index
            .commit_snapshot(
                1,
                &fixture.frame(false),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        let expected = if scenario == "archived" {
            original
        } else {
            "[]".into()
        };
        assert_eq!(
            index.search(&actor, &now).await.unwrap(),
            expected,
            "live {scenario}"
        );
        drop(index);
        let reopened = CurrentIndexHarness::open(&id, 2).await.unwrap();
        assert_eq!(
            reopened.search(&actor, &now).await.unwrap(),
            expected,
            "reopened {scenario}"
        );
    }
}

#[wasm_bindgen_test(async)]
async fn search_authorization_context_uses_one_complete_cut_on_cold_reopen() {
    for case in search_circle::authorization_cases() {
        let id = authority(&format!("search-authorization-{}", case.name));
        let index = CurrentIndexHarness::open(&id, 0).await.unwrap();
        let fixture = &case.fixture;
        let message = arkret_sdk::MessageId::from_event_id(&fixture.message.event.event_id);
        let holder = serde_json::to_string(&fixture.actor).unwrap();
        let requester = serde_json::to_string(&case.requester).unwrap();
        let now = search_circle::at(20).to_rfc3339();
        assert_eq!(
            index
                .commit(0, &case.cached_originals_frame())
                .await
                .unwrap(),
            1
        );
        assert!(
            index
                .search_originals_present(message.as_str())
                .await
                .unwrap()
        );
        assert_eq!(
            index.search(&holder, &now).await.unwrap(),
            "[]",
            "missing cut {}",
            case.name
        );
        let generation = index
            .commit_snapshot(
                1,
                &fixture.frame(true),
                &serde_json::to_string(&fixture.snapshot).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(generation, 2);
        let expected = serde_json::to_string(&if case.visible {
            vec![fixture.message.clone()]
        } else {
            vec![]
        })
        .unwrap();
        case.assert_search_result(
            index.search(&requester, &now).await,
            expected.clone(),
            "live",
        );
        if !case.malformed_current {
            assert_eq!(
                index.search(&holder, &now).await.unwrap(),
                serde_json::to_string(&vec![fixture.message.clone()]).unwrap(),
                "holder control {}",
                case.name
            );
        }
        drop(index);
        let cold = CurrentIndexHarness::open(&id, generation).await.unwrap();
        assert!(
            cold.search_originals_present(message.as_str())
                .await
                .unwrap()
        );
        case.assert_search_result(cold.search(&requester, &now).await, expected, "cold");
    }
}

/// One IndexedDB database backs every account, so each test owns an authority
/// of its own and never reads another test's committed generation.
fn authority(label: &str) -> String {
    let unique = js_sys::Date::now() as u64;
    json!({
        "principal_id": format!("ak:did_core:web:{label}-{unique}.example"),
        "station_id": format!("ak:did_core:web:station-{label}.example"),
    })
    .to_string()
}

fn selector() -> String {
    json!({"kind":"realm_profile"}).to_string()
}

const OTHER_REALM: &str = "ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";
const CURSORS: [&str; 3] = ["ak:cursor:YQ", "ak:cursor:Yg", "ak:cursor:Yw"];

fn member_selector(actor: &str) -> String {
    json!({"kind":"member_state","actor_id":{"kind":"service","service_id":actor}}).to_string()
}

/// One Realm entry whose current value is the profile row, or a member row when
/// `actor` is given, optionally carrying a complete or pending baseline.
fn realm_frame(
    realm: &str,
    revision: u64,
    actor: Option<&str>,
    baseline: Option<(&str, bool)>,
) -> String {
    let (selector, value) = match actor {
        Some(actor) => (
            serde_json::from_str::<serde_json::Value>(&member_selector(actor)).unwrap(),
            json!({"membership":"join"}),
        ),
        None => (
            serde_json::from_str::<serde_json::Value>(&selector()).unwrap(),
            json!({"status":"value","value":null}),
        ),
    };
    let heads = json!([{
        "stream_ref":{"kind":"realm","realm_id":realm},
        "stream_position":5,
        "commit_id":COMMIT
    }]);
    let mut entry = json!({"current":{
        "realm_id":realm,
        "governance_generation":"1",
        "stream_heads": if baseline.is_some() { heads.clone() } else { json!([]) },
        "entries":[{
            "selector":selector,
            "source_stream_ref":{"kind":"realm","realm_id":realm},
            "revision":{"commit_id":COMMIT,"stream_position":revision},
            "value":value,
        }]
    }});
    if let Some((snapshot, complete)) = baseline {
        entry["baseline"] = json!({
            "snapshot_cursor":snapshot,
            "cut_revision":5,
            "coverage":{
                "realm_id":realm,
                "stream_heads":heads,
                "complete_for_authorized_streams":true
            },
            "complete":complete
        });
    }
    json!({"kind":"delta","cursor":"ak:cursor:YQ","realms":{realm:entry}}).to_string()
}

fn frame(revision: u64, removed: bool) -> String {
    let entry = json!({
        "selector": serde_json::from_str::<serde_json::Value>(&selector()).unwrap(),
        "source_stream_ref": {"kind":"realm","realm_id":REALM},
        "revision": {"commit_id":COMMIT,"stream_position":revision},
        "value": if removed { json!({"status":"removed"}) } else { json!({"status":"value","value":null}) },
    });
    json!({"kind":"delta","cursor":"ak:cursor:YQ",
    "realms":{REALM:{"current":{
        "realm_id":REALM,"governance_generation":"1","stream_heads":[],"entries":[entry]
    }}}})
    .to_string()
}

#[wasm_bindgen_test(async)]
async fn a_failed_stage_stays_invisible_and_retries_at_the_same_generation() {
    let id = authority("failed-stage");
    let first = CurrentIndexHarness::open(&id, 0).await.unwrap();
    first.abandon(0, &frame(1, false)).await.unwrap();
    assert_eq!(first.read_ready(REALM, &selector()).await.unwrap(), None);
    drop(first);

    let restored = CurrentIndexHarness::open(&id, 0).await.unwrap();
    assert_eq!(restored.commit(0, &frame(2, true)).await.unwrap(), 1);
    let installed = restored
        .read_ready(REALM, &selector())
        .await
        .unwrap()
        .unwrap();
    assert!(installed.contains("\"stream_position\":2"), "{installed}");
    assert!(installed.contains("removed"), "{installed}");
    drop(restored);

    let committed = CurrentIndexHarness::open(&id, 1).await.unwrap();
    assert!(
        committed
            .read_ready(REALM, &selector())
            .await
            .unwrap()
            .is_some()
    );
    // The retried generation delivered other content at the same revision.
    assert!(committed.commit(1, &frame(2, false)).await.is_err());
}

#[wasm_bindgen_test(async)]
async fn an_unconfirmed_durable_result_poisons_the_pointer() {
    let id = authority("poison");
    let store = CurrentIndexHarness::open(&id, 0).await.unwrap();
    store.abandon_armed(0, &frame(1, false)).await.unwrap();
    assert!(store.is_poisoned());
    // Nothing may reuse the generation whose durable result is unknown.
    assert!(store.commit(0, &frame(2, false)).await.is_err());
    assert!(store.maintain().await.is_err());
    assert!(store.confirm_durable_pointer(2).is_err());
    assert!(store.is_poisoned());

    store.confirm_durable_pointer(0).unwrap();
    assert!(!store.is_poisoned());
    assert_eq!(store.read_ready(REALM, &selector()).await.unwrap(), None);
    assert_eq!(store.commit(0, &frame(2, false)).await.unwrap(), 1);
    let installed = store.read_ready(REALM, &selector()).await.unwrap().unwrap();
    assert!(installed.contains("\"stream_position\":2"), "{installed}");
}

#[wasm_bindgen_test(async)]
async fn a_cancelled_install_recovers_only_the_confirmed_pointer() {
    let id = authority("cancelled");
    let store = CurrentIndexHarness::open(&id, 0).await.unwrap();
    store
        .persist_unconfirmed(0, &frame(1, false))
        .await
        .unwrap();
    assert!(store.is_poisoned());
    store.confirm_durable_pointer(1).unwrap();
    let installed = store.read_ready(REALM, &selector()).await.unwrap().unwrap();
    assert!(installed.contains("\"stream_position\":1"), "{installed}");
    drop(store);

    // A restart may only open at a generation whose manifest is durable.
    assert!(CurrentIndexHarness::open(&id, 2).await.is_err());
    let restored = CurrentIndexHarness::open(&id, 1).await.unwrap();
    assert!(
        restored
            .read_ready(REALM, &selector())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(restored.commit(1, &frame(3, false)).await.unwrap(), 2);
}

#[wasm_bindgen_test(async)]
async fn the_same_revision_with_other_content_is_rejected() {
    let id = authority("conflict");
    let store = CurrentIndexHarness::open(&id, 0).await.unwrap();
    assert_eq!(store.commit(0, &frame(5, false)).await.unwrap(), 1);
    assert!(store.commit(1, &frame(5, true)).await.is_err());
    // The rejected frame left the installed value exactly as it was.
    let installed = store.read_ready(REALM, &selector()).await.unwrap().unwrap();
    assert!(installed.contains("\"stream_position\":5"), "{installed}");
    assert!(!installed.contains("removed"), "{installed}");
    assert_eq!(store.commit(1, &frame(6, true)).await.unwrap(), 2);

    // Maintenance batches deletes and cursor advances into one IndexedDB
    // transaction; running it must not change what a reader sees.
    for _ in 0..24 {
        store.maintain().await.unwrap();
    }
    let installed = store.read_ready(REALM, &selector()).await.unwrap().unwrap();
    assert!(installed.contains("\"stream_position\":6"), "{installed}");
}

#[wasm_bindgen_test(async)]
async fn repeated_baselines_reclaim_only_unreferenced_seen_evidence() {
    let id = authority("reclaim");
    let store = CurrentIndexHarness::open(&id, 0).await.unwrap();
    for (generation, snapshot) in CURSORS.iter().enumerate() {
        store
            .commit(
                generation as u64,
                &realm_frame(REALM, 1, None, Some((snapshot, true))),
            )
            .await
            .unwrap();
    }
    for snapshot in CURSORS {
        assert_eq!(
            store
                .seen_versions(snapshot, REALM, &selector())
                .await
                .unwrap(),
            1
        );
    }
    for _ in 0..80 {
        store.maintain().await.unwrap();
    }
    // Only the snapshot the Realm still roots keeps its IndexedDB evidence.
    for (snapshot, expected) in CURSORS.iter().zip([0, 0, 1]) {
        assert_eq!(
            store
                .seen_versions(snapshot, REALM, &selector())
                .await
                .unwrap(),
            expected,
            "{snapshot}"
        );
    }
    assert!(
        store
            .read_ready(REALM, &selector())
            .await
            .unwrap()
            .is_some()
    );
}

#[wasm_bindgen_test(async)]
async fn a_root_published_after_the_mark_cursor_survives_the_same_sweep() {
    let id = authority("barrier");
    let store = CurrentIndexHarness::open(&id, 0).await.unwrap();
    store
        .commit(0, &realm_frame(REALM, 1, None, Some((CURSORS[0], true))))
        .await
        .unwrap();
    let mut passes = 0;
    while !store.gc_position().await.unwrap().1 {
        store.maintain().await.unwrap();
        passes += 1;
        assert!(passes < 40, "the mark phase did not terminate");
    }
    // The mark scan is already past this Realm; only the publish write barrier
    // can protect the snapshot this frame roots.
    store
        .commit(1, &realm_frame(REALM, 1, None, Some((CURSORS[1], false))))
        .await
        .unwrap();
    let (epoch, _) = store.gc_position().await.unwrap();
    passes = 0;
    while store.gc_position().await.unwrap().0 == epoch {
        store.maintain().await.unwrap();
        passes += 1;
        assert!(passes < 40, "the sweep did not terminate");
    }
    assert_eq!(
        store
            .seen_versions(CURSORS[1], REALM, &selector())
            .await
            .unwrap(),
        1
    );
    assert!(
        store
            .read_ready(REALM, &selector())
            .await
            .unwrap()
            .is_some()
    );
    // Publishing on every pass still lets whole cycles finish.
    let (epoch, _) = store.gc_position().await.unwrap();
    let mut generation = 2;
    passes = 0;
    while store.gc_position().await.unwrap().0 < epoch + 2 {
        store
            .commit(generation, &realm_frame(REALM, generation + 10, None, None))
            .await
            .unwrap();
        generation += 1;
        store.maintain().await.unwrap();
        passes += 1;
        assert!(passes < 120, "continuous writes restarted the cycle");
    }
}

#[wasm_bindgen_test(async)]
async fn another_realm_reference_keeps_a_shared_snapshot_alive() {
    let id = authority("shared");
    let first = "ak:did_core:webvh:z6mkfirst";
    let second = "ak:did_core:webvh:z6mksecond";
    let store = CurrentIndexHarness::open(&id, 0).await.unwrap();
    store
        .commit(
            0,
            &realm_frame(REALM, 1, Some(first), Some((CURSORS[0], true))),
        )
        .await
        .unwrap();
    store
        .commit(
            1,
            &realm_frame(OTHER_REALM, 1, Some(second), Some((CURSORS[0], true))),
        )
        .await
        .unwrap();
    store
        .commit(2, &realm_frame(REALM, 1, None, Some((CURSORS[1], true))))
        .await
        .unwrap();
    for _ in 0..80 {
        store.maintain().await.unwrap();
    }
    // The other Realm still roots the shared snapshot, so it survives as a
    // unit, while the first Realm's moved-off evidence is no longer readable.
    assert_eq!(
        store
            .seen_versions(CURSORS[0], OTHER_REALM, &member_selector(second))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .read_ready(REALM, &member_selector(first))
            .await
            .unwrap(),
        None
    );
    assert!(
        store
            .read_ready(OTHER_REALM, &member_selector(second))
            .await
            .unwrap()
            .is_some()
    );
    store
        .commit(
            3,
            &realm_frame(OTHER_REALM, 1, Some(second), Some((CURSORS[2], true))),
        )
        .await
        .unwrap();
    for _ in 0..120 {
        store.maintain().await.unwrap();
    }
    for (realm, actor) in [(REALM, first), (OTHER_REALM, second)] {
        assert_eq!(
            store
                .seen_versions(CURSORS[0], realm, &member_selector(actor))
                .await
                .unwrap(),
            0
        );
    }
    assert!(
        store
            .read_ready(OTHER_REALM, &member_selector(second))
            .await
            .unwrap()
            .is_some()
    );
}

#[wasm_bindgen_test(async)]
async fn opening_the_secret_store_never_decrypts_current_entries() {
    use inkson::secure_key_store::{IndexedDbSecureKeyStore, SecureKeyStore};

    let id = authority("secret-cache");
    let store = CurrentIndexHarness::open(&id, 0).await.unwrap();
    store
        .commit(0, &realm_frame(REALM, 1, None, Some((CURSORS[0], true))))
        .await
        .unwrap();
    assert!(
        store
            .seen_versions(CURSORS[0], REALM, &selector())
            .await
            .unwrap()
            > 0
    );
    // Login opens the secret store and loads its synchronous cache. The index
    // shares the IndexedDB object store, and none of its rows may be decrypted
    // into that cache.
    let secrets = IndexedDbSecureKeyStore::new_async("inkson").await.unwrap();
    assert_eq!(
        secrets
            .list_secret_keys(Some(store.storage_prefix()))
            .unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        secrets
            .list_secret_keys(Some("inkson.current.v1/"))
            .unwrap(),
        Vec::<String>::new()
    );
}

/// Every product-ready row of `realm`, read in pages of `limit`.
async fn realm_rows(store: &CurrentIndexHarness, realm: &str, limit: usize) -> Vec<String> {
    let mut rows = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let (page, next) = store
            .read_realm_page(realm, after.as_deref(), limit)
            .await
            .unwrap();
        assert!(page.len() <= limit);
        rows.extend(page);
        match next {
            Some(next) => after = Some(next),
            None => return rows,
        }
    }
}

/// One Realm entry carrying `rows` member rows of `membership`, as one segment
/// of a frozen baseline when `baseline` is given.
fn member_frame(
    realm: &str,
    actors: std::ops::Range<usize>,
    revision: u64,
    membership: &str,
    baseline: Option<(&str, u64, bool)>,
) -> String {
    let heads = |cut: u64| {
        json!([{
            "stream_ref":{"kind":"realm","realm_id":realm},
            "stream_position":cut,
            "commit_id":COMMIT
        }])
    };
    let entries = actors
        .map(|n| {
            json!({
                "selector": serde_json::from_str::<serde_json::Value>(&member_selector(&format!(
                    "ak:did_core:webvh:z6mkactor{n:04}"
                )))
                .unwrap(),
                "source_stream_ref":{"kind":"realm","realm_id":realm},
                "revision":{"commit_id":COMMIT,"stream_position":revision},
                "value":{"membership":membership},
            })
        })
        .collect::<Vec<_>>();
    let mut entry = json!({"current":{
        "realm_id":realm,
        "governance_generation":"1",
        "stream_heads": baseline.map_or_else(|| json!([]), |(_, cut, _)| heads(cut)),
        "entries":entries
    }});
    if let Some((snapshot, cut, complete)) = baseline {
        entry["baseline"] = json!({
            "snapshot_cursor":snapshot,
            "cut_revision":cut,
            "coverage":{
                "realm_id":realm,
                "stream_heads":heads(cut),
                "complete_for_authorized_streams":true
            },
            "complete":complete
        });
    }
    json!({"kind":"delta","cursor":"ak:cursor:YQ","realms":{realm:entry}}).to_string()
}

#[wasm_bindgen_test(async)]
async fn product_reads_page_the_realm_and_revocation_pends_only_its_realm() {
    let id = authority("product-view");
    let store = CurrentIndexHarness::open(&id, 0).await.unwrap();
    // 150 member rows arrive as two segments of one frozen baseline.
    store
        .commit(
            0,
            &member_frame(REALM, 0..100, 1, "join", Some((CURSORS[0], 5, false))),
        )
        .await
        .unwrap();
    store
        .commit(
            1,
            &member_frame(REALM, 100..150, 1, "join", Some((CURSORS[0], 5, true))),
        )
        .await
        .unwrap();
    store
        .commit(
            2,
            &member_frame(OTHER_REALM, 0..1, 1, "join", Some((CURSORS[1], 5, true))),
        )
        .await
        .unwrap();
    let rows = realm_rows(&store, REALM, 40).await;
    assert_eq!(rows.len(), 150);
    assert_eq!(
        rows.iter().collect::<std::collections::BTreeSet<_>>().len(),
        150
    );
    assert_eq!(realm_rows(&store, OTHER_REALM, 40).await.len(), 1);

    // A revocation is one live row of its own selector past the cut.
    store
        .commit(3, &member_frame(REALM, 0..1, 6, "ban", None))
        .await
        .unwrap();
    let rows = realm_rows(&store, REALM, 100).await;
    assert_eq!(rows.len(), 150);
    assert_eq!(rows.iter().filter(|row| row.contains("\"ban\"")).count(), 1);

    // An invalidation of this Realm leaves its rows pending; the other Realm's
    // first screen is not held back by it.
    let invalidation = json!({
        "kind":"delta","cursor":"ak:cursor:YQ",
        "realm_invalidations":[{"realm_id":REALM,"revision":6}]
    })
    .to_string();
    store.commit(4, &invalidation).await.unwrap();
    assert!(realm_rows(&store, REALM, 100).await.is_empty());
    assert_eq!(realm_rows(&store, OTHER_REALM, 100).await.len(), 1);

    // A fresh complete baseline without the revoked half hides it at once and
    // bounded maintenance reclaims it without touching the other Realm.
    store
        .commit(
            5,
            &member_frame(REALM, 60..150, 7, "join", Some((CURSORS[2], 8, true))),
        )
        .await
        .unwrap();
    assert_eq!(realm_rows(&store, REALM, 100).await.len(), 90);
    for _ in 0..200 {
        store.maintain().await.unwrap();
        assert_eq!(realm_rows(&store, OTHER_REALM, 100).await.len(), 1);
    }
    assert_eq!(realm_rows(&store, REALM, 100).await.len(), 90);
    for n in 0..60 {
        assert_eq!(
            store
                .read_ready(
                    REALM,
                    &member_selector(&format!("ak:did_core:webvh:z6mkactor{n:04}"))
                )
                .await
                .unwrap(),
            None
        );
    }
}
