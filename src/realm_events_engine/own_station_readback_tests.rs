use serde_json::json;

use super::*;

#[test]
fn bound_readback_session_guard_is_safe_inside_the_store_write_callback() {
    let account = crate::test_support::authority_at_station(
        "did:web:alice.example",
        "ak:did_core:web:test-server.example",
    );
    let (client, server) =
        crate::transport::own_station_results::test_http::client(&account, vec![]);
    let epoch = crate::identity::device_directory::session_cache_epoch();
    let directory = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(std::sync::Mutex::new(
        crate::state::LocalStateStore::with_path(directory.path().join("state.json")),
    ));
    let write_store = store.clone();
    let handle = crate::runtime::input::StateStoreHandle::new(
        |_| panic!("the in-transaction session guard must not re-read the store signal"),
        move |write| write(&mut write_store.lock().unwrap()),
    );
    let session_active = || require_readback_session(&client, &account, epoch).is_ok();
    handle.write(|_| assert!(session_active()));
    server.join().unwrap();
}

fn readback_ids() -> (
    arkret_sdk::RealmId,
    arkret_sdk::SidecarId,
    arkret_sdk::EventId,
) {
    (
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
        arkret_sdk::SidecarId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [118; 32],
        )),
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [119; 32]),
    )
}

#[test]
fn accepted_identity_and_author_plaintext_cannot_replace_verified_native_history() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = crate::state::LocalStateStore::with_path(directory.path().join("state.json"));
    store.switch_test_account("did:web:alice.example");
    let account = store.active_authority().unwrap();
    let (realm, sidecar, event) = readback_ids();
    let strand = "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let message = arkret_sdk::MessageId::from_event_id(&event);
    store.append_raw_operation(
        "accepted-local-operation",
        Some(realm.to_string()),
        json!({"event_id":event, "kind":arkret_sdk::EventKind::MessageCreate.as_str(),
            "strand_id":strand, "message_id":message, "encrypted_content":true,
            "status":"committed"}),
    );
    store.save_private_plaintext(
        realm.as_str(),
        strand,
        &format!("message:{message}"),
        "private author text",
    );
    assert_eq!(store.load().raw_operations.len(), 1);
    assert!(store.verified_sidecar_inputs(realm.as_str()).is_err());
    assert!(require_accepted_sidecar_event(&store, &account, &realm, &sidecar, &event).is_err());
    assert_eq!(store.load().raw_operations.len(), 1);
    assert_eq!(store.active_authority().as_ref(), Some(&account));
}
