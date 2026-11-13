use super::*;
use crate::views::chat::native_harness::NativeHarness;

#[tokio::test(flavor = "current_thread")]
async fn accepted_cache_barrier_keeps_later_draft_clear_and_replacement_account() {
    use futures_util::FutureExt;

    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
    let dir = tempfile::tempdir().unwrap();
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let strand = "ak:strand:01964137-0000-7000-8000-000000000002";
    for change in ["draft", "clear", "replacement"] {
        let dom = NativeHarness::new();
        let context = dom.context(dir.path().join(format!("{change}.json")));
        {
            let store = context.state_store.clone();
            store.write(|store| store.switch_test_account("did:web:alice.example"));
            let authority = store.read(|store| store.active_authority()).unwrap();
            let secure = MemorySecureKeyStore::new();
            let (key, initial) = store
                .write(|store| {
                    store.prepare_composer_draft_write(
                        &authority,
                        &device,
                        realm,
                        strand,
                        "old draft".to_owned(),
                    )
                })
                .unwrap();
            LocalStateStore::persist_e2ee_plaintext_cache_write_durable(
                &secure,
                &key,
                initial.as_deref(),
            )
            .now_or_never()
            .unwrap()
            .unwrap();
            store.write(|store| {
                store.save_private_plaintext(
                    realm,
                    strand,
                    "message:accepted",
                    "accepted sidecar text",
                )
            });
            let (release, ready) = tokio::sync::oneshot::channel();
            let mut write = Box::pin(persist_chat_cache_after_account_barrier(
                store.clone(),
                &authority,
                async move { ready.await.map_err(anyhow::Error::from) },
                || true,
                &secure,
            ));
            assert!(write.as_mut().now_or_never().is_none());
            // A real draft/clear write completes while the accepted send waits.
            match change {
                "draft" => {
                    let (key, json) = store
                        .write(|store| {
                            store.prepare_composer_draft_write(
                                &authority,
                                &device,
                                realm,
                                strand,
                                "latest draft".to_owned(),
                            )
                        })
                        .unwrap();
                    LocalStateStore::persist_e2ee_plaintext_cache_write_durable(
                        &secure,
                        &key,
                        json.as_deref(),
                    )
                    .now_or_never()
                    .unwrap()
                    .unwrap();
                }
                "clear" => {
                    let clear = store
                        .write(|store| {
                            store.prepare_e2ee_plaintext_cache_clear(
                                &crate::state::E2eePlaintextCacheClearScope::All,
                            )
                        })
                        .unwrap()
                        .unwrap();
                    clear.persist(&secure).now_or_never().unwrap().unwrap();
                }
                _ => {
                    store.write(|store| store.switch_test_account("did:web:bob.example"));
                }
            }
            let before_release = secure.get_secret(&key).unwrap();
            release.send(()).unwrap();
            let result = write.as_mut().now_or_never().unwrap();
            if change == "replacement" {
                assert!(result.unwrap_err().to_string().contains("previous account"));
                assert_eq!(secure.get_secret(&key).unwrap(), before_release);
            } else {
                result.unwrap();
                let mut restart =
                    LocalStateStore::with_path(dir.path().join(format!("{change}-restart.json")));
                restart.switch_test_account("did:web:alice.example");
                restart
                    .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
                    .unwrap();
                assert_eq!(
                    restart.composer_draft(&device, realm, strand),
                    if change == "draft" {
                        "latest draft"
                    } else {
                        ""
                    }
                );
                assert_eq!(
                    restart.private_plaintext_for(realm, strand, "message:accepted"),
                    (change == "draft").then(|| "accepted sidecar text".to_owned())
                );
            }
        };
    }
}

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
