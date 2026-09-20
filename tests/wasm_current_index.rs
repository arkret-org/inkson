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

fn frame(revision: u64, removed: bool) -> String {
    let entry = json!({
        "selector": serde_json::from_str::<serde_json::Value>(&selector()).unwrap(),
        "revision": {"commit_id":COMMIT,"stream_position":revision},
        "value": if removed { json!({"status":"removed"}) } else { json!({"status":"value","value":null}) },
    });
    json!({"kind":"delta","cursor":"ak:cursor:YQ",
    "realms":{REALM:{"current":{
        "realm_id":REALM,"governance_generation":1,"stream_heads":[],"entries":[entry]
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
    store.abandon_armed(0, &frame(1, false)).await.unwrap();
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
