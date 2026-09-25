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
        "governance_generation":1,
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
