//! Chat view tests, split by the behaviour under test.
//!
//! `use super::*;` pulls the parent `chat` module symbols into this `tests`
//! module; the `pub(super)` re-export republishes them so each
//! `tests/<sub>.rs` doing `use super::*;` (whose `super` is THIS module)
//! transitively sees the chat symbols. Fixtures shared by more than one
//! submodule live here; fixtures used by exactly one live with it.

pub(super) use super::*;
pub(super) use crate::test_support as fixture;

mod channels;
mod crypto_state;
mod event_parsing;
mod mention_candidates;
mod mentions;
mod merge_alignment;
mod message_fold;
mod operations;
mod participation;
mod presence;
mod read_receipts;
mod sender_display;
mod sidecar_restore;
mod sidecar_routing;

/// Station this client authors at under test (`operation::authoring_station_id`
/// default). Mention subjects are complete accounts, so fixtures must name a
/// Station explicitly.
pub(super) const LOCAL_STATION_ID: &str = "ak:did_core:web:principal.example";
pub(super) const REMOTE_STATION_ID: &str = "ak:did_core:web:remote-station.example";

/// Complete account for a fixture principal at `station`.
pub(super) fn fixture_account(principal_id: &str, station: &str) -> arkret_sdk::AccountId {
    arkret_sdk::AccountId::new(
        crate::mls_api_helpers::principal_core_id(principal_id).expect("fixture principal id"),
        arkret_sdk::DidCoreId::new(station.to_owned()).expect("fixture station id"),
    )
}

/// Complete account for a fixture principal hosted by this client's Station.
pub(super) fn local_fixture_account(principal_id: &str) -> arkret_sdk::AccountId {
    fixture_account(principal_id, LOCAL_STATION_ID)
}

/// Membership identity for a fixture principal hosted by this client's Station.
pub(super) fn local_fixture_actor(principal_id: &str) -> arkret_sdk::ActorId {
    arkret_sdk::ActorId::account(local_fixture_account(principal_id))
}

fn sidecar_projection_message(id: &str, strand_id: &str, body: &str) -> ChatMessage {
    sidecar_projection_message_for_realm(
        "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw",
        id,
        strand_id,
        body,
    )
}

fn sidecar_projection_message_for_realm(
    realm_id: &str,
    id: &str,
    strand_id: &str,
    body: &str,
) -> ChatMessage {
    ChatMessage {
        realm_id: realm_id.to_owned(),
        id: id.to_owned(),
        protocol_message_id: None,
        actor_id: None,
        sender: "ak:did_core:web:example.test:alice".to_owned(),
        executed_by: None,
        body: body.to_owned(),
        content_format: None,
        timestamp: "12:00".to_owned(),
        created_at: None,
        strand_id: strand_id.to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    }
}

const CHAT_FIXTURE_DEVICE: &str = "ak:device:01964137-0000-7000-8000-00000000cafe";
const CHAT_FIXTURE_SEED: [u8; 32] = [91; 32];

fn sign_chat_fixture(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                sign_chat_fixture(value);
            }
        }
        Value::Object(object) => {
            for child in object.values_mut() {
                sign_chat_fixture(child);
            }
            let Some(actor_id) = object.get("actor_id").and_then(|value| {
                serde_json::from_value::<arkret_sdk::ActorId>(value.clone()).ok()
            }) else {
                return;
            };
            let actor_core_id = actor_id.signing_principal_id().clone();
            // Proof fixtures need an exact DID for their verification
            // URL. These fixtures use reversible did:web ids only; production
            // code never performs this core-to-full reconstruction.
            let signer_did = actor_core_id
                .as_str()
                .strip_prefix("ak:did_core:web:")
                .map(|suffix| format!("did:web:{suffix}"))
                .unwrap_or_else(|| actor_core_id.as_str().to_owned());
            object.insert("device_id".to_owned(), json!(CHAT_FIXTURE_DEVICE));
            object.remove("proofs");
            object.remove("unsigned");
            let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
                CHAT_FIXTURE_SEED,
                &signer_did,
                format!("{signer_did}#{CHAT_FIXTURE_DEVICE}"),
            );
            // The `encoding.md` §6 preimage comes from the SDK. A fixture signer
            // that restates the rule is how this file once signed bytes no
            // verifier could reproduce.
            let preimage = arkret_sdk::event_digest_preimage(value).unwrap();
            let canonical_bytes = crate::canonical::canonical_json_bytes(&preimage).unwrap();
            let event_digest = crate::canonical::sha256_digest(&canonical_bytes);
            let mut proof = arkret_sdk::ProducerEventProof {
                kind: "detached_jws".to_owned(),
                verification_method: arkret_sdk::DidUrl::new(
                    signer.verification_method().to_owned(),
                )
                .unwrap(),
                event_digest: arkret_sdk::Hash::new(event_digest).unwrap(),
                signer_resolution_evidence_ref: Some(
                    arkret_sdk::SignerEvidenceRef::new(format!(
                        "ak:signer_evidence:sha256:{}",
                        "11".repeat(32)
                    ))
                    .unwrap(),
                ),
                created_at: chrono::DateTime::parse_from_rfc3339("2026-07-10T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: String::new(),
            };
            let binding = proof.canonical_binding_bytes(&actor_id).unwrap();
            proof.jws = signer.detached_jws_over(&binding).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert("proofs".to_owned(), json!([proof]));

            let signing_key = ed25519_dalek::SigningKey::from_bytes(&CHAT_FIXTURE_SEED);
            let did_key =
                crate::identity::did_key::did_key_from_verifying_key(&signing_key.verifying_key());
            let public_key =
                crate::identity::device_directory::public_key_from_directory_value(&did_key)
                    .unwrap();
            crate::identity::device_directory::seed_positive_for_test(
                actor_core_id.as_str(),
                CHAT_FIXTURE_DEVICE,
                public_key,
            );
        }
        _ => {}
    }
}

fn sign_chat_fixtures(values: &mut [Value]) {
    for value in values {
        sign_chat_fixture(value);
    }
}
