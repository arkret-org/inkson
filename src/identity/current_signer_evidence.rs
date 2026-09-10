//! Fresh signing authority from the authenticated Account Station.

use arkret_sdk::{
    AccountDeviceSenderKind, AgentSenderKind, CurrentAccountDeviceSelector, CurrentAdmissionMode,
    CurrentAgentSelector, SignerKeyQueryOutcome, SignerKeyQuerySelector,
    SignerKeysQueryRequestBody,
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
        Some(device_id) => {
            SignerKeyQuerySelector::CurrentAccountDevice(CurrentAccountDeviceSelector {
                verification_mode: CurrentAdmissionMode::CurrentAdmission,
                sender_kind: AccountDeviceSenderKind::AccountDevice,
                actor: envelope.sender_actor_id.clone(),
                device_id: device_id.clone(),
                verification_method: envelope.proof.verification_method.clone(),
            })
        }
        None => SignerKeyQuerySelector::CurrentAgent(CurrentAgentSelector {
            verification_mode: CurrentAdmissionMode::CurrentAdmission,
            sender_kind: AgentSenderKind::Agent,
            actor: envelope.sender_actor_id.clone(),
            verification_method: envelope.proof.verification_method.clone(),
        }),
    };
    let request = SignerKeysQueryRequestBody {
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
        .signer_keys_query(&request)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "current Signal signer evidence query failed");
        })
        .ok()?;
    outcome.validate_for_request(&request).ok()?;
    let mut results = outcome.results.into_iter();
    let SignerKeyQueryOutcome::Current(result) = results.next()? else {
        return None;
    };
    if results.next().is_some()
        || result.selector != selector
        || result.key.actor != envelope.sender_actor_id
        || result.key.verification_method != envelope.proof.verification_method
    {
        return None;
    }
    Some(result.key)
}
