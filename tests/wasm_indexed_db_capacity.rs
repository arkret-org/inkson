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
        .expect("persist entry larger than the legacy localStorage quota");
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
