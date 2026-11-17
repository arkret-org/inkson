//! Read producer-signed Welcome deliveries from the durable endpoint inbox.

use arkret_wire::MlsWelcomeDelivery;

/// Every producer-signed Welcome delivery this device has journalled but not
/// consumed yet.
///
/// The durable to-device inbox is a weakly typed journal, so the only sound
/// test for "this row is a Welcome" is that its `content` parses closed into
/// `MlsWelcomeDelivery` and passes the delivery's own shape validation. A
/// Welcome is not an Event and carries no Event kind, so there is nothing else
/// to match on.
pub(crate) fn welcome_from_inbox_row(message: &serde_json::Value) -> Option<MlsWelcomeDelivery> {
    let value = if message
        .get("delivery_kind")
        .and_then(serde_json::Value::as_str)
        == Some("mls_welcome")
    {
        message.get("mls_welcome")?
    } else {
        message.get("content")?
    };
    serde_json::from_value::<MlsWelcomeDelivery>(value.clone())
        .ok()
        .filter(|delivery| delivery.validate_shape().is_ok())
}

pub(crate) fn pending_welcome_deliveries(
    messages: &[serde_json::Value],
) -> Vec<MlsWelcomeDelivery> {
    messages.iter().filter_map(welcome_from_inbox_row).collect()
}

/// The pending Welcome deliveries that belong to one Realm.
pub(crate) fn welcome_deliveries_for_realm(
    messages: &[serde_json::Value],
    realm_id: &str,
) -> Vec<MlsWelcomeDelivery> {
    pending_welcome_deliveries(messages)
        .into_iter()
        .filter(|delivery| delivery.realm_id.as_str() == realm_id.trim())
        .collect()
}

/// A stable dedup hint over the Welcome deliveries pending for one Realm.
///
/// UI effects fold this into their `seen` key so a Welcome that arrives after
/// an earlier empty probe re-triggers the join drain. The hint is derived from
/// the delivery ids, which are unique and immutable
/// (`ak:mls_welcome_delivery:<uuidv7>`), so it changes exactly when the set of
/// pending Welcomes changes.
pub(crate) fn local_mls_welcome_hint_for_realm(
    messages: &[serde_json::Value],
    realm_id: &str,
) -> String {
    let mut ids = welcome_deliveries_for_realm(messages, realm_id)
        .into_iter()
        .map(|delivery| delivery.welcome_id.as_str().to_owned())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    format!("{}:{}", ids.len(), ids.join(","))
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{Event, EventId, Hash};
    use arkret_wire::{
        DetachedObjectSignature, DetachedSignatureAlgorithm, DetachedSignatureContext,
        KeypackageClaimId, MlsWelcomeDeliveryId, MlsWelcomeRecipientEndpoint,
    };

    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000001";

    fn realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new(REALM).unwrap()
    }

    fn scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        }
    }

    fn actor() -> arkret_sdk::ActorId {
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn producer_proof() -> DetachedObjectSignature {
        DetachedObjectSignature {
            context: DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap(),
            signed_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            created_at: "2026-09-16T00:00:00.000Z".parse().unwrap(),
            signature: arkret_wire::Base64UrlString::new(arkret_sdk::base64url_encode([7_u8; 64]))
                .unwrap(),
        }
    }

    /// One accepted `ak.mls.commit` that advances the Realm scope to epoch 4.
    fn commit_event() -> Event {
        let binding = arkret_sdk::MlsGovernanceBindingPayload::realm(
            realm_id(),
            Some(EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [9; 32],
            )),
            3,
            4,
            0,
        )
        .unwrap();
        let commit_bytes = [1_u8, 2, 3, 4];
        let envelope = arkret_sdk::MlsCommitEnvelope {
            group_id: binding.mls_group_id().unwrap(),
            epoch: 4,
            commit: arkret_sdk::base64url_encode(commit_bytes),
            commit_digest: Hash::new(arkret_sdk::canonical::sha256_digest(commit_bytes)).unwrap(),
            ratchet_tree: None,
        };
        let payload = {
            let public_material = {
                let bytes = arkret_sdk::base64url_decode(&envelope.commit).unwrap();
                (bytes.clone(), bytes)
            };
            let (info, tree) =
                crate::test_support::content::public_refs(&public_material.0, &public_material.1);
            arkret_sdk::MlsCommitPayload::new(
                EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [9; 32]),
                0,
                &envelope,
                binding,
                info,
                tree,
            )
        }
        .unwrap();
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::MlsCommit>::new(
            scope(),
            actor(),
            payload,
        )
        .unwrap()
        .author_with_digest_suite(
            "2026-09-16T00:00:00.000Z".parse().unwrap(),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap()
        .into_event()
    }

    fn delivery(commit: &Event) -> MlsWelcomeDelivery {
        MlsWelcomeDelivery {
            welcome_id: MlsWelcomeDeliveryId::new(
                "ak:mls_welcome_delivery:0196419b-0000-7000-8000-00000000000a",
            )
            .unwrap(),
            realm_id: realm_id(),
            effective_scope: scope(),
            commit_event_ref: commit.event_id.clone(),
            recipient_actor_id: actor(),
            recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
                device_id: arkret_sdk::DeviceId::new(DEVICE).unwrap(),
            },
            keypackage_claim_ref: KeypackageClaimId::new(
                "ak:keypackage_claim:0196419b-0000-7000-8000-00000000000b",
            )
            .unwrap(),
            ciphertext_base64url: arkret_wire::Base64UrlString::new(arkret_sdk::base64url_encode(
                [5_u8; 48],
            ))
            .unwrap(),
            producer_proof: producer_proof(),
        }
    }

    /// One durable to-device inbox row carrying `delivery` as its content.
    fn inbox_row(delivery: &MlsWelcomeDelivery) -> serde_json::Value {
        serde_json::json!({
            "message_id": delivery.welcome_id.as_str(),
            "content": serde_json::to_value(delivery).unwrap(),
        })
    }

    #[test]
    fn only_rows_that_parse_as_a_closed_delivery_are_pending_welcomes() {
        let commit = commit_event();
        let delivery = delivery(&commit);
        let mut malformed = inbox_row(&delivery);
        malformed["content"]["effective_scope"] = serde_json::json!({ "kind": "realm_genesis" });
        let messages = vec![
            serde_json::json!({ "message_id": "m1", "content": { "kind": "read_receipt" } }),
            inbox_row(&delivery),
            // A delivery whose scope fails `validate_shape` is never admitted.
            malformed,
        ];
        let pending = pending_welcome_deliveries(&messages);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].welcome_id, delivery.welcome_id);
    }

    #[test]
    fn signed_welcome_branch_is_journalled_without_device_message_wrapping() {
        let delivery = delivery(&commit_event());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("welcome-journal.json");
        let mut writer = crate::state::LocalStateStore::with_path(path.clone());
        let branch = arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
            mls_welcome: delivery.clone(),
        };
        assert_eq!(
            writer
                .ingest_recipient_deliveries(std::slice::from_ref(&branch))
                .unwrap(),
            1
        );
        assert_eq!(writer.ingest_recipient_deliveries(&[branch]).unwrap(), 0);
        let reopened = crate::state::LocalStateStore::with_path(path);
        let inbox = reopened.to_device_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0]["delivery_kind"], "mls_welcome");
        assert!(inbox[0].get("content").is_none());
        assert_eq!(
            pending_welcome_deliveries(&inbox)[0].welcome_id,
            delivery.welcome_id
        );
    }

    #[test]
    fn the_welcome_hint_changes_only_when_the_pending_set_changes() {
        let commit = commit_event();
        let delivery = delivery(&commit);
        let empty = local_mls_welcome_hint_for_realm(&[], REALM);
        let one = local_mls_welcome_hint_for_realm(&[inbox_row(&delivery)], REALM);
        assert_ne!(empty, one);
        // A repeated journal row is the same Welcome, so the hint is stable.
        assert_eq!(
            one,
            local_mls_welcome_hint_for_realm(&[inbox_row(&delivery), inbox_row(&delivery)], REALM)
        );
        // A Welcome for another Realm never leaks into this Realm's hint.
        assert_eq!(
            empty,
            local_mls_welcome_hint_for_realm(
                &[inbox_row(&delivery)],
                "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN"
            )
        );
        assert_eq!(
            welcome_deliveries_for_realm(&[inbox_row(&delivery)], REALM).len(),
            1
        );
    }
}
