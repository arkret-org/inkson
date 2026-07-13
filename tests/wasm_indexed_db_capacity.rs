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
