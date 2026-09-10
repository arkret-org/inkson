//! Fresh signing authority from the authenticated Account Station.

use arkret_models_collaboration::{
    CurrentSignerEvidenceSelector, SelfCurrentSignerEvidenceQueryRequestBody,
    SelfCurrentSignerEvidenceResult,
};
pub(crate) async fn query_for_signal(
    http: &arkret_sdk::http_client::Client,
    envelope: &arkret_wire::SignalEnvelope,
    recipient_account_id: arkret_sdk::AccountId,
) -> Option<arkret_sdk::StationSigningKey> {
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
    let request = SelfCurrentSignerEvidenceQueryRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        realm_id: envelope.realm_id.clone(),
        recipient_account_id,
        queries: vec![selector.clone()],
    };
    request
        .validate()
        .map_err(|error| tracing::warn!(%error, "current Signal evidence request is invalid"))
        .ok()?;
    let outcome = http
        .current_signer_evidence_query(&request)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "current Signal signer evidence query failed");
        })
        .ok()?;
    outcome.validate_for_request(&request).ok()?;
    let mut results = outcome.results.into_iter();
    let SelfCurrentSignerEvidenceResult::Resolved {
        selector: resolved_selector,
        key,
        ..
    } = results.next()?
    else {
        return None;
    };
    if results.next().is_some()
        || resolved_selector != selector
        || key.actor != envelope.sender_actor_id
        || key.verification_method != envelope.proof.verification_method
    {
        return None;
    }
    Some(key)
}
