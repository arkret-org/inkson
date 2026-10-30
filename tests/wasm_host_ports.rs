//! Exercise the real Inkson adapter and encrypted IndexedDB account store.
#![cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]

use garth::mls::checkpoint::{MlsLocalCheckpointEnvelope, decrypt_with_epoch_check};
use inkson::mls::checkpoint_harness::CheckpointHarness;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test(async)]
async fn shared_checkpoint_port_survives_reopening_the_browser_host_store() {
    inkson::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
        .await
        .unwrap();
    let encoded = include_str!("../../garth/tests/fixtures/checkpoint-v1.json");
    let expected: MlsLocalCheckpointEnvelope = serde_json::from_str(encoded).unwrap();
    let scope = serde_json::to_string(&arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(&expected.realm_id).unwrap(),
    })
    .unwrap();
    let accepted = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [9; 32]);
    let host = CheckpointHarness::default();
    host.install(&scope, encoded, accepted.as_str())
        .await
        .unwrap();
    let installed = host.checkpoint(&scope).unwrap().unwrap();
    drop(host);
    let reopened = CheckpointHarness::default()
        .checkpoint(&scope)
        .unwrap()
        .unwrap();
    assert_eq!(installed, reopened);
    let checkpoint: MlsLocalCheckpointEnvelope = serde_json::from_str(&reopened).unwrap();
    assert_eq!(checkpoint.group_state_event_id.as_ref(), Some(&accepted));
    assert_eq!(checkpoint.epoch, expected.epoch);
    assert_eq!(
        decrypt_with_epoch_check(&checkpoint, "portable-checkpoint-fixture", 7).unwrap(),
        b"opaque RFC 9420 provider checkpoint"
    );
}
