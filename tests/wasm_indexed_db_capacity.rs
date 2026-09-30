#![cfg(target_arch = "wasm32")]

use inkson::secure_key_store::{IndexedDbSecureKeyStore, SecureKeyStore};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test(async)]
async fn default_product_store_delegates_atomic_queue_writes_to_indexeddb() {
    inkson::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
        .await
        .unwrap();
    let store = inkson::secure_key_store::default_secure_key_store("inkson");
    let key = inkson::outbound_store_test_api::outbound_queue_key(
        &format!("nsProduct{}", js_sys::Date::now()),
        "standard",
    );
    inkson::outbound_store_test_api::mutate_outbound_queue(store.as_ref(), &key, |queue| {
        queue.enqueue(contract_submission(0), chrono::Utc::now())?;
        Ok(())
    })
    .await
    .unwrap();
    let reopened_holder = inkson::secure_key_store::default_secure_key_store("inkson");
    let count = inkson::outbound_store_test_api::mutate_outbound_queue(
        reopened_holder.as_ref(),
        &key,
        |queue| Ok(queue.items().len()),
    )
    .await
    .unwrap();
    assert_eq!(count, 1);
    assert!(browser_local_storage().get_item(&key).unwrap().is_none());
}

#[wasm_bindgen_test(async)]
async fn independent_holders_compare_exchange_only_the_committed_winner() {
    let service_name = format!("atomic-secret-test-{}", js_sys::Date::now());
    let first = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .unwrap();
    let second = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        first.compare_exchange_secret_bytes_durable("queue", None, b"first"),
        second.compare_exchange_secret_bytes_durable("queue", None, b"second"),
    );
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_ne!(left, right, "exactly one absent-entry contender commits");
    let expected = if left {
        b"first".as_slice()
    } else {
        b"second".as_slice()
    };
    assert_eq!(
        first
            .read_secret_bytes_durable("queue")
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        expected,
    );
    assert_eq!(
        second
            .read_secret_bytes_durable("queue")
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        expected,
        "an independent holder reads the backend winner even with a stale cache",
    );
    assert!(
        !second
            .compare_exchange_secret_bytes_durable("queue", None, b"stale")
            .await
            .unwrap()
    );
    assert!(
        second
            .compare_exchange_secret_bytes_durable("queue", Some(expected), b"next")
            .await
            .unwrap()
    );
    let reopened = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .unwrap();
    assert_eq!(
        reopened.get_secret("queue").unwrap().as_deref(),
        Some("next")
    );
}

#[wasm_bindgen_test(async)]
async fn binary_secret_and_text_round_trip_across_reopen() {
    let service_name = format!("binary-secret-test-{}", js_sys::Date::now());
    let secret = (0_u8..=255).collect::<Vec<_>>();
    let writer = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .unwrap();
    writer
        .store_secret_bytes_durable("binary", &secret)
        .await
        .unwrap();
    writer
        .store_secret_durable("text", "text-secret")
        .await
        .unwrap();
    assert_eq!(
        writer
            .get_secret_bytes("binary")
            .unwrap()
            .unwrap()
            .as_slice(),
        secret.as_slice()
    );
    drop(writer);

    let reader = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .unwrap();
    assert_eq!(
        reader
            .get_secret_bytes("binary")
            .unwrap()
            .unwrap()
            .as_slice(),
        secret.as_slice()
    );
    assert_eq!(
        reader.get_secret("text").unwrap().as_deref(),
        Some("text-secret")
    );
}

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
    store
        .compare_exchange_secret_bytes_durable(key, Some(b"committed"), b"phantom")
        .await
        .expect_err("compare exchange against a closed database must fail");
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
// run the production read-modify-write code (through
// `inkson::outbound_store_test_api`, which only exists so the store can be
// passed in) against a real IndexedDB tier.

const CONTRACT_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

/// One ordinary, structurally valid submission. These contracts are about the
/// storage tier, so the item only has to be something `SendQueue::enqueue`
/// accepts and `from_snapshot` reads back.
fn contract_submission(nth: usize) -> garth::QueuedSubmission {
    use inkson::operation::AuthoredEventExt as _;

    let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
    ));
    let payload = arkret_sdk::MessageCreatePayload::with_content(
        arkret_sdk::StrandId::new("ak:strand:AXA352XtBodUhnMN_nDxOloEHVn0_yAotxiYxbyU38Df")
            .unwrap(),
        "discussion",
        arkret_sdk::ContentBlock::text(format!("queued contract {nth} {}", "x".repeat(2048))),
    );
    let mut event = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::MessageCreate>::new(
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(CONTRACT_REALM.to_owned()).unwrap(),
        },
        actor_id,
        payload,
    )
    .unwrap()
    .author_with_digest_suite(
        chrono::DateTime::from_timestamp_millis(
            1_760_000_000_000 + i64::try_from(nth).unwrap_or(0),
        )
        .unwrap(),
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap();
    event
        .sign_ed25519(
            "did:web:alice.example",
            "did:web:alice.example#key-1",
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        )
        .expect("contract Event has a real producer proof");
    garth::QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission {
            event: event.into_event(),
            approval_signatures: None,
        },
    ))
    .expect("contract submission is structurally valid")
}

fn fill_queue(queue: &mut garth::SendQueue, count: usize) {
    let now = chrono::Utc::now();
    for index in 0..count {
        queue
            .enqueue(contract_submission(index), now)
            .expect("enqueue contract item");
    }
}

#[wasm_bindgen_test(async)]
async fn independent_queue_holders_retry_the_original_frozen_items_after_conflict() {
    let service_name = format!("outbound-atomic-{}", js_sys::Date::now());
    let key = inkson::outbound_store_test_api::outbound_queue_key("nsAtomic", "standard");
    let first = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .unwrap();
    let second = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .unwrap();
    let left = contract_submission(0);
    let right = contract_submission(1);
    let (left_result, right_result) = tokio::join!(
        inkson::outbound_store_test_api::mutate_outbound_queue(&first, &key, |queue| {
            queue.enqueue(left.clone(), chrono::Utc::now())?;
            Ok(())
        }),
        inkson::outbound_store_test_api::mutate_outbound_queue(&second, &key, |queue| {
            queue.enqueue(right.clone(), chrono::Utc::now())?;
            Ok(())
        }),
    );
    assert!(left_result.is_ok() || right_result.is_ok());
    for (store, result, original) in [
        (&first, left_result, &left),
        (&second, right_result, &right),
    ] {
        if let Err(error) = result {
            assert!(error.to_string().contains("changed in another holder"));
            inkson::outbound_store_test_api::mutate_outbound_queue(store, &key, |queue| {
                queue.enqueue(original.clone(), chrono::Utc::now())?;
                Ok(())
            })
            .await
            .unwrap();
        }
    }
    let reopened = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .unwrap();
    inkson::outbound_store_test_api::mutate_outbound_queue(&reopened, &key, |queue| {
        assert_eq!(queue.items().len(), 2);
        for original in [&left, &right] {
            let expected = serde_json::to_vec(&original.request).unwrap();
            assert!(
                queue
                    .items()
                    .iter()
                    .any(|item| serde_json::to_vec(&item.submission.request).unwrap() == expected)
            );
        }
        Ok(())
    })
    .await
    .unwrap();
}

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
            let items = queue.items();
            Ok((
                items.len(),
                items.first().unwrap().event_id().clone(),
                items.last().unwrap().event_id().clone(),
            ))
        })
        .await
        .expect("reload the persisted queue");
    assert_eq!(items, 2048, "every queued item must survive the reload");
    assert_eq!(first, contract_submission(0).event_id);
    assert_eq!(last, contract_submission(2047).event_id);
}

#[wasm_bindgen_test(async)]
async fn localstorage_queue_is_not_imported_into_the_secure_store() {
    let service_name = format!("outbound-isolation-{}", js_sys::Date::now());
    let store = IndexedDbSecureKeyStore::new_async(&service_name)
        .await
        .expect("open store");
    let storage = browser_local_storage();
    let key = inkson::outbound_store_test_api::outbound_queue_key("nsObsolete", "standard");
    let mut queue = garth::SendQueue::default();
    fill_queue(&mut queue, 2);
    let obsolete = serde_json::to_string(&queue.snapshot()).unwrap();
    storage
        .set_item(&key, &obsolete)
        .expect("seed obsolete queue");
    let count = inkson::outbound_store_test_api::mutate_outbound_queue(&store, &key, |queue| {
        Ok(queue.items().len())
    })
    .await
    .expect("open current queue");
    assert_eq!(
        count, 0,
        "plaintext historical entries must not enter the queue"
    );
    storage.remove_item(&key).expect("remove test fixture");
}
