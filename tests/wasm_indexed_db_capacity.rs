#![cfg(target_arch = "wasm32")]

use inkson::secure_key_store::{IndexedDbSecureKeyStore, SecureKeyStore};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test(async)]
async fn large_entry_round_trips_across_reopen() {
    let service_name = format!("capacity-test-{}", js_sys::Date::now());
    let key = "inkson.e2ee_plaintext_cache.v1.capacity-test";
    let secret = "x".repeat(12 * 1024 * 1024);

    let writer = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .expect("open writer store");
    writer
        .store_secret_durable(key, &secret)
        .await
        .expect("persist entry larger than the localStorage quota");
    drop(writer);

    let reader = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .expect("reopen reader store");
    assert_eq!(
        reader
            .get_secret(key)
            .expect("read persisted entry")
            .as_deref(),
        Some(secret.as_str())
    );
}

#[wasm_bindgen_test(async)]
#[cfg(feature = "wasm-localstorage-secrets-test")]
async fn failed_durable_write_does_not_publish_a_phantom_cache_value() {
    let service_name = format!("durable-failure-test-{}", js_sys::Date::now());
    let key = "inkson.e2ee_plaintext_cache.v1.durable-failure";
    let store = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .expect("open store");
    store
        .store_secret_durable(key, "committed")
        .await
        .expect("seed committed value");
    store.close_database_for_test();

    store
        .store_secret_durable(key, "phantom")
        .await
        .expect_err("write against a closed database must fail");
    assert_eq!(
        store.get_secret(key).expect("read cache").as_deref(),
        Some("committed"),
        "a failed durable write must leave the last committed cache value visible"
    );

    let reopened = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .expect("reopen store after failed write");
    assert_eq!(
        reopened
            .get_secret(key)
            .expect("read durable value after reopen")
            .as_deref(),
        Some("committed"),
        "a failed durable write must not survive a database reopen"
    );
}

#[wasm_bindgen_test(async)]
#[cfg(feature = "wasm-localstorage-secrets-test")]
async fn account_state_fault_injection_contract_holds_in_browser() {
    inkson::run_browser_account_persist_fault_contract()
        .await
        .expect("browser account-state persistence contract");
}

// ── Durable outbound queue ───────────────────────────────────────────────────
//
// The queue moved off localStorage because one queue of signed, not-yet-sent
// Events routinely exceeds the whole ~5 MB per-origin budget. These contracts
// run the production adoption / read-modify-write code (through
// `inkson::outbound_store_test_api`, which only exists so the store can be
// passed in) against a real IndexedDB tier.

const CONTRACT_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

#[cfg(target_arch = "wasm32")]
fn contract_record() -> garth::QueuedRecord {
    let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
    ));
    let event: arkret_sdk::Event = serde_json::from_value(serde_json::json!({
        "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind": "ak.presence",
        "realm_id": CONTRACT_REALM,
        "scope_ref": {"kind": "realm", "realm_id": CONTRACT_REALM},
        "actor_id": actor_id,
        "actor_seq": 1,
        "created_at": "2026-05-19T00:00:00.000Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "prev_refs": [],
        "payload": {"actor_id": actor_id, "state": "online"},
        "proofs": []
    }))
    .unwrap();
    garth::QueuedRecord::SdkEvent(Box::new(
        garth::QueuedSdkEvent::unauthored(
            garth::QueuedEventIntent::new(
                arkret_event_draft::EventIntent::from_authored(&event),
                arkret_sdk::DigestSuite::Sha256,
            ),
            "local-operation".to_owned(),
            "attempt".to_owned(),
            None,
            garth::AuthoringGeneration {
                authority_model: garth::AuthoringAuthorityModel::AcceptedDevice,
                authority_principal_id: arkret_sdk::DidCoreId::new(
                    "ak:did_core:web:alice.example".to_owned(),
                )
                .unwrap(),
                generation_ref: "1-QmCurrent".to_owned(),
            },
            None,
        )
        .unwrap(),
    ))
}

#[cfg(target_arch = "wasm32")]
fn fill_queue(queue: &mut garth::SendQueue, count: usize) {
    let realm = arkret_sdk::RealmId::new(CONTRACT_REALM.to_owned()).unwrap();
    let now = chrono::Utc::now();
    for index in 0..count {
        queue
            .enqueue(
                Some(format!("txn-{index}")),
                realm.clone(),
                contract_record(),
                Vec::new(),
                now,
            )
            .expect("enqueue contract item");
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_local_storage() -> web_sys::Storage {
    web_sys::window()
        .expect("window")
        .local_storage()
        .expect("local storage access")
        .expect("local storage present")
}

#[wasm_bindgen_test(async)]
async fn outbound_queue_past_the_localstorage_quota_round_trips_in_indexeddb() {
    let service_name = format!("outbound-capacity-{}", js_sys::Date::now());
    let key = inkson::outbound_store_test_api::outbound_queue_key("nsCapacity", "standard");

    let writer = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .expect("open writer store");
    inkson::outbound_store_test_api::mutate_outbound_queue(&writer, &key, |queue| {
        fill_queue(queue, 2048);
        Ok(())
    })
    .await
    .expect("persist a queue larger than the localStorage quota");
    let encoded_len = writer
        .get_secret(&key)
        .expect("read back the encoded queue")
        .expect("queue is present")
        .len();
    assert!(
        encoded_len > 5 * 1024 * 1024,
        "contract queue is only {encoded_len} bytes and no longer exceeds the quota it tests"
    );
    drop(writer);

    // Reopening is the reload: the cache is rebuilt by decrypting IndexedDB,
    // so this asserts the queue survived the tier, not the process.
    let reader = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .expect("reopen reader store");
    let (items, first, last) =
        inkson::outbound_store_test_api::mutate_outbound_queue(&reader, &key, |queue| {
            let active = queue.active_items();
            Ok((
                queue.len(),
                active.first().unwrap().transaction_id.clone(),
                active.last().unwrap().transaction_id.clone(),
            ))
        })
        .await
        .expect("reload the persisted queue");
    assert_eq!(items, 2048, "every queued item must survive the reload");
    assert_eq!(first, "txn-0");
    assert_eq!(last, "txn-2047");
}

#[wasm_bindgen_test(async)]
async fn legacy_localstorage_queues_are_adopted_or_discarded_by_account_index() {
    let service_name = format!("outbound-migration-{}", js_sys::Date::now());
    let store = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .expect("open store");
    let storage = browser_local_storage();
    let root_key = "inkson.local_state.v1";

    let mut queue = garth::SendQueue::new();
    fill_queue(&mut queue, 2);
    let legacy_json = serde_json::to_string(&queue.snapshot()).expect("encode legacy queue");

    // 1. Root index unreadable (absent) => "unknown", so every queue is
    //    adopted rather than risk discarding unsent Events.
    let _ = storage.remove_item(root_key);
    let adopt_key = inkson::outbound_store_test_api::outbound_queue_key("nsAdopt", "standard");
    storage
        .set_item(&adopt_key, &legacy_json)
        .expect("seed a legacy queue");

    inkson::outbound_store_test_api::drain_legacy_outbound_queues(&store)
        .await
        .expect("drain legacy queues");

    assert_eq!(
        store.get_secret(&adopt_key).expect("read adopted queue"),
        Some(legacy_json.clone()),
        "an adopted queue must reach the secure tier byte for byte"
    );
    assert_eq!(
        storage.get_item(&adopt_key).expect("read localStorage"),
        None,
        "the legacy copy is removed only after the durable copy is committed"
    );

    // 2. A parsed root index that lists no profile is a trustworthy answer:
    //    the queue's authority is gone, its items can never be signed or sent,
    //    and copying them forward would migrate unreachable work.
    storage
        .set_item(root_key, "{\"known_profiles\":[]}")
        .expect("seed an empty account index");
    let discard_key = inkson::outbound_store_test_api::outbound_queue_key("nsGone", "standard");
    storage
        .set_item(&discard_key, &legacy_json)
        .expect("seed an abandoned queue");

    inkson::outbound_store_test_api::drain_legacy_outbound_queues(&store)
        .await
        .expect("drain abandoned queues");

    assert_eq!(
        storage.get_item(&discard_key).expect("read localStorage"),
        None,
        "an abandoned queue is removed"
    );
    assert_eq!(
        store.get_secret(&discard_key).expect("read secure tier"),
        None,
        "an abandoned queue is not carried into the secure tier"
    );

    let _ = storage.remove_item(root_key);
}
