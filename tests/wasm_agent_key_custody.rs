#![cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]

use inkson::secure_key_store::{IndexedDbSecureKeyStore, SecureKeyStore};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test(async)]
async fn product_agent_keys_are_durable_and_never_mirror_or_fall_back() {
    let key = format!("agent.did.keys.custody-{}", js_sys::Date::now());
    let fallback = web_sys::window().unwrap().local_storage().unwrap().unwrap();
    let before_init = inkson::secure_key_store::default_secure_key_store("inkson");
    assert!(
        before_init
            .store_secret_durable(&key, "must fail before initialization")
            .await
            .is_err()
    );
    assert!(fallback.get_item(&key).unwrap().is_none());
    inkson::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
        .await
        .unwrap();
    let store = inkson::secure_key_store::default_secure_key_store("inkson");
    store
        .store_secret_durable(&key, "committed Agent binding material")
        .await
        .unwrap();
    assert!(fallback.get_item(&key).unwrap().is_none());
    let cold = IndexedDbSecureKeyStore::new_async("inkson").await.unwrap();
    assert_eq!(
        cold.read_secret_bytes_durable(&key)
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        b"committed Agent binding material"
    );
    inkson::secure_key_store::close_wasm_product_database_for_test().unwrap();
    assert!(
        store
            .store_secret_durable(&key, "uncommitted replacement")
            .await
            .is_err()
    );
    assert!(fallback.get_item(&key).unwrap().is_none());
    let missing = format!(
        "inkson.account.agent.did.keys.missing-{}",
        js_sys::Date::now()
    );
    assert!(
        store
            .store_secret_durable(&missing, "must not downgrade")
            .await
            .is_err()
    );
    assert!(fallback.get_item(&missing).unwrap().is_none());
    let reopened = IndexedDbSecureKeyStore::new_async("inkson").await.unwrap();
    assert_eq!(
        reopened
            .read_secret_bytes_durable(&key)
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        b"committed Agent binding material"
    );
    assert!(
        reopened
            .read_secret_bytes_durable(&missing)
            .await
            .unwrap()
            .is_none()
    );
}
