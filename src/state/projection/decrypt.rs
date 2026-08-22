use serde_json::Value;

use crate::state::LocalStateStore;

#[allow(clippy::too_many_arguments)]
pub(crate) fn try_local_mls_decrypt_core_for_scope_from_verified_sender(
    state_store: &LocalStateStore,
    realm_id: &str,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    payload_value: &Value,
    effective_scope: &arkret_sdk::ScopeRef,
    event_kind: &str,
    verified_sender_domain: &[u8],
    reaction_routing_window: Option<u64>,
) -> Option<Vec<u8>> {
    // Network Events must use the canonical EncryptedEnvelope. Falling back to
    // a raw internal EncryptedPayload would bypass reconstruction of the
    // authenticated header, so malformed envelopes stay opaque.
    let envelope =
        serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(payload_value.clone()).ok()?;
    let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
        state_store,
        &envelope,
        effective_scope,
        event_kind,
        verified_sender_domain,
        reaction_routing_window,
    )?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
        state_store,
        secure_store.as_ref(),
        realm_id,
        authority,
        actor_id,
        device_id,
        &payload,
        effective_scope,
        verified_sender_domain,
    )
}
