use super::*;

#[tokio::test]
async fn inactive_readback_preserves_accepted_identity_without_touching_the_replacement_store() {
    let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();
    let account = crate::test_support::authority_at_station(
        "did:web:alice.example",
        "ak:did_core:web:test-server.example",
    );
    let realm =
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let sidecar = arkret_sdk::SidecarId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [118; 32],
    ));
    let event = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [119; 32]);
    let untouched = crate::runtime::input::StateStoreHandle::new(
        |_| panic!("inactive readback must not read a replacement namespace"),
        |_| panic!("inactive readback must not write a replacement namespace"),
    );
    let history = crate::realm_events_engine::refresh_accepted_sidecar(
        &http,
        &account,
        0,
        &realm,
        &sidecar,
        &event,
        untouched,
        || false,
    )
    .await
    .map_err(anyhow::Error::from);
    assert!(
        history
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("replaced session")
    );
    let accepted = SourceRoutedSidecarMessageOutcome::after_accept(event.to_string(), history);
    assert_eq!(accepted.event_id, event.to_string());
    assert!(
        accepted
            .history_pending
            .as_deref()
            .unwrap()
            .contains("replaced session")
    );
}
