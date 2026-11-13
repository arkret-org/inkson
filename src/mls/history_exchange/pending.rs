//! A loaded page cannot prove completion of a cut-wide history exchange.
//! Keep the exact request private key for delayed grants until expiry or an
//! independently established terminal condition, such as endpoint replacement.
use super::*;

pub(super) async fn expire_request(
    vault: &HistoryExchangeVault<'_>,
    scope: &ScopeRef,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    if let Some(pending) = vault.request(scope).await?
        && pending.has_private_key()
        && pending.event().as_mls_history_request()?.expires_at <= now
    {
        vault
            .consume_request(scope, &pending.event().event_id)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_test_kit::signed_event::SignedEventFixtureBuilder;
    use arkret_test_kit::{keys, subjects};

    use super::*;

    #[tokio::test]
    async fn partial_page_progress_preserves_private_custody_for_late_grants_until_expiry() {
        // Real HPKE and durable CAS; native disclosure qualification is tested
        // at its independent server/accepted-original boundary.
        let fixture =
            arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
                .unwrap();
        let mut grant: HistoryGrant =
            serde_json::from_value(fixture["hpke_grant"]["grant"].clone()).unwrap();
        grant.recipient.actor_id = ActorId::account(subjects::alice_account_id());
        grant.recipient.endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
            device_id: subjects::alice_device_id(),
        };
        let hpke = arkret_crypto::hpke::generate_x25519_keypair().unwrap();
        let at = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let request = HistoryRequest {
            recipient: grant.recipient.clone(),
            recipient_hpke_key_base64url: arkret_sdk::canonical::base64url_encode(
                hpke.public_key(),
            ),
            history_cut: grant.history_cut.clone(),
            expires_at: at + chrono::Duration::seconds(600),
        };
        let scope = ScopeRef::Realm {
            realm_id: request.history_cut.stream_ref.realm_id().clone(),
        };
        let signer =
            keys::seeded_signer(subjects::alice_did(), subjects::alice_verification_method());
        let event = SignedEventFixtureBuilder::new(
            "ak.mls.history_request",
            scope.clone(),
            request.recipient.actor_id.clone(),
            serde_json::to_value(&request).unwrap(),
        )
        .with_created_at(at)
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        let store = garth::MemorySecureKeyStore::default();
        let vault = HistoryExchangeVault::new(
            &store,
            &request.recipient.actor_id,
            &request.recipient.endpoint,
        );
        vault
            .freeze_request(
                PendingHistoryRequest::new(event.clone(), hpke.private_key()).unwrap(),
                at,
            )
            .await
            .unwrap();
        grant.recipient_key_event_ref = event.event_id.clone();
        grant.recipient_hpke_key_base64url = request.recipient_hpke_key_base64url.clone();
        grant.expires_at = request.expires_at;
        grant.entries.clear();
        for (path, secret) in [
            ("/payload/encrypted_content", [83u8; 16]),
            ("/payload/encrypted_metadata", [91u8; 16]),
        ] {
            grant.entries.clear();
            let selector = HistoryKeySelector::ContentKey {
                source_event_ref: grant.history_cut.event_id.clone(),
                content_path: path.into(),
            };
            let sealed =
                arkret_crypto::content_history::seal_history_key(&grant, &selector, &secret)
                    .unwrap();
            grant.entries.push(HistoryGrantEntry {
                selector,
                sealed_key_base64url: sealed,
            });
            // A second view/page can discover its grant after the first page
            // has no missing known sources. That is not a consumption proof.
            expire_request(&vault, &scope, at + chrono::Duration::seconds(120))
                .await
                .unwrap();
            let reopened = vault.request(&scope).await.unwrap().unwrap();
            assert_eq!(reopened.event(), &event);
            assert!(reopened.has_private_key());
            assert_eq!(
                reopened
                    .open_entry(
                        &grant,
                        &grant.entries[0],
                        at + chrono::Duration::seconds(120)
                    )
                    .unwrap()
                    .as_slice(),
                secret
            );
        }
        expire_request(&vault, &scope, request.expires_at)
            .await
            .unwrap();
        let expired = vault.request(&scope).await.unwrap().unwrap();
        assert!(!expired.has_private_key());
        assert!(
            expired
                .open_entry(&grant, &grant.entries[0], request.expires_at)
                .is_err()
        );
    }
}
