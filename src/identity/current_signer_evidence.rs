//! Authenticated refresh of reusable current signer authority.

use arkret_models_collaboration::{
    CurrentSignerEvidenceQueryOutcome, CurrentSignerEvidenceQueryRequestBody,
    CurrentSignerEvidenceSelector,
};
pub(crate) async fn query_for_signal(
    http: &arkret_sdk::http_client::Client,
    envelope: &arkret_wire::SignalEnvelope,
    recipient_account_id: arkret_sdk::AccountId,
    known_agent_state_digests: Vec<arkret_sdk::Hash>,
    known_signer_evidence_refs: Vec<arkret_sdk::SignerEvidenceRef>,
) -> Option<(
    CurrentSignerEvidenceQueryRequestBody,
    CurrentSignerEvidenceQueryOutcome,
)> {
    envelope
        .validate_structural()
        .map_err(|error| tracing::warn!(%error, "current Signal evidence envelope is invalid"))
        .ok()?;
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
    let request = CurrentSignerEvidenceQueryRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        realm_id: envelope.realm_id.clone(),
        recipient_account_id,
        queries: vec![selector],
        known_agent_state_digests,
        known_signer_evidence_refs,
    };
    request
        .validate_for_envelope(envelope)
        .map_err(|error| tracing::warn!(%error, "current Signal evidence request is invalid"))
        .ok()?;
    let outcome = http
        .current_signer_evidence_query(&request)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "current Signal signer evidence query failed");
        })
        .ok()?;
    Some((request, outcome))
}
