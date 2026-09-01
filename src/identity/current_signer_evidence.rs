//! Cold-recipient acquisition of origin-signed current Signal authority.

use arkret_models_collaboration::{
    CurrentSignerEvidenceQueryOutcome, CurrentSignerEvidenceQueryRequestBody,
    CurrentSignerEvidenceSelector,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::identity::device_directory::DidAnchor as _;

pub(crate) async fn query_for_signal(
    http: &arkret_sdk::http_client::Client,
    envelope: &arkret_wire::SignalEnvelope,
    recipient_account_id: arkret_sdk::AccountId,
    anchor: &crate::identity::did_resolver::ResolverDidAnchor,
) -> Option<(
    CurrentSignerEvidenceQueryRequestBody,
    CurrentSignerEvidenceQueryOutcome,
)> {
    envelope.validate_structural().ok()?;
    let selector = match envelope.sender_device_id.as_ref() {
        Some(device_id) => CurrentSignerEvidenceSelector::AccountDevice {
            account_id: envelope.sender_actor_id.as_account_id()?.clone(),
            device_id: device_id.clone(),
        },
        None => CurrentSignerEvidenceSelector::Agent {
            actor: envelope.sender_actor_id.clone(),
            verification_method: envelope.proof.verification_method.clone(),
        },
    };
    let mut random = [0_u8; 24];
    getrandom::fill(&mut random).ok()?;
    let nonce = URL_SAFE_NO_PAD.encode(random);
    let request = CurrentSignerEvidenceQueryRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        realm_id: envelope.realm_id.clone(),
        operation_id: arkret_sdk::ServiceOperationId::SelfSignalCommandSendV1,
        request_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
            &arkret_sdk::canonical::canonical_json_bytes(envelope).ok()?,
        ))
        .ok()?,
        recipient_account_id,
        challenge: arkret_sdk::NonEmptyString::new(format!("ak.challenge:{nonce}")).ok()?,
        queries: vec![selector],
    };
    request.validate_for_envelope(envelope).ok()?;
    let outcome = http.current_signer_evidence_query(&request).await.ok()?;
    let method_did =
        arkret_sdk::verification_method_did(outcome.proof.verification_method.as_str()).ok()?;
    let document = match anchor.resolve_did_document(&method_did) {
        Some(document) => document,
        None => {
            let client = reqwest::Client::new();
            if !anchor.ensure_actor_document(&client, &method_did).await {
                return None;
            }
            anchor.resolve_did_document(&method_did)?
        }
    };
    arkret_sdk::identity::validate_verification_method_relationship(
        &document,
        &outcome.proof.verification_method,
        &method_did,
        arkret_sdk::identity::DidVerificationRelationship::AssertionMethod,
    )
    .ok()?;
    let key = arkret_sdk::resolve_verification_method_key_from_document(
        &document,
        outcome.proof.verification_method.as_str(),
    )
    .ok()?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(&key.public_key.ed25519_bytes().ok()?).ok()?;
    arkret_sdk::signatures::current_signer_evidence::verify_current_signer_evidence_outcome(
        &outcome,
        &key,
        chrono::Utc::now(),
    )
    .ok()?;
    Some((request, outcome))
}
