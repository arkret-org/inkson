use serde_json::Value;

use crate::state::LocalStateStore;

pub(crate) fn try_local_mls_decrypt_from_verified_original(
    state_store: &LocalStateStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    payload_value: &Value,
    original: &arkret_sdk::Event,
    verified_sender_domain: &[u8],
) -> Option<Vec<u8>> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    try_local_mls_decrypt_from_verified_original_with_secure_store(
        state_store,
        realm_id,
        authority,
        device_id,
        payload_value,
        original,
        verified_sender_domain,
        secure_store.as_ref(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn try_local_mls_decrypt_from_verified_original_with_secure_store(
    state_store: &LocalStateStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    payload_value: &Value,
    original: &arkret_sdk::Event,
    verified_sender_domain: &[u8],
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Option<Vec<u8>> {
    if original.realm_id.as_str() != realm_id {
        return None;
    }
    // Network Events must use the canonical EncryptedEnvelope. Falling back to
    // a raw internal EncryptedPayload would bypass reconstruction of the
    // authenticated header, so malformed envelopes stay opaque.
    let envelope =
        serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(payload_value.clone()).ok()?;
    let payload = crate::mls::runtime::encrypted_payload_from_verified_original(
        state_store,
        secure_store,
        authority,
        device_id,
        original,
        &envelope,
        verified_sender_domain,
    )?;
    crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
        state_store,
        secure_store,
        realm_id,
        authority,
        device_id,
        &payload,
        &original.scope_ref,
        verified_sender_domain,
    )
}
