use serde_json::Value;

use crate::state::LocalStateStore;

/// Shared MLS decrypt core used by chat decrypt-on-read and Board
/// decrypt-on-read callers.
///
/// YOU-02-004 (`encryption-and-audit.md` §5.6): this is no longer a
/// read-only replay — a successful decrypt persists the advanced MLS
/// receive chain (via the store's interior-mutable receive-chain overlay)
/// and caches the plaintext under the envelope's `payload_digest`, so
/// re-renders and restarts are served from the cache instead of replaying
/// the ratchet from a stale snapshot. Every soft failure (no snapshot,
/// wrong/absent device secret, payload that doesn't deserialize or
/// decrypt — including the author's own ciphertext, which OpenMLS rejects)
/// returns `None`.
pub(crate) fn try_local_mls_decrypt_core_for_effective_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload_value: &Value,
    circle_id: Option<&str>,
) -> Option<Vec<u8>> {
    let realm_id_typed = arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?;
    let effective_scope = match circle_id {
        Some(circle_id) => arkret_sdk::ScopeRef::Circle {
            realm_id: realm_id_typed,
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).ok()?,
        },
        None => arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id_typed,
        },
    };
    try_local_mls_decrypt_core_for_scope(
        state_store,
        realm_id,
        actor_id,
        device_id,
        payload_value,
        &effective_scope,
    )
}

pub(crate) fn try_local_mls_decrypt_core_for_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload_value: &Value,
    effective_scope: &arkret_sdk::ScopeRef,
) -> Option<Vec<u8>> {
    // Network Events must use the canonical EncryptedEnvelope. Falling back to
    // a raw EncryptedPayload would turn a missing/invalid scope_digest into an
    // authentication bypass, so malformed or pre-contract envelopes stay
    // opaque and require an explicit migration outside the receive path.
    let envelope =
        serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(payload_value.clone()).ok()?;
    envelope.validate_for_scope(effective_scope).ok()?;
    let payload = arkret_sdk::mls::encrypted_envelope_to_payload(&envelope).ok()?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    crate::mls::runtime::decrypt_application_payload_for_scope(
        state_store,
        secure_store.as_ref(),
        realm_id,
        actor_id,
        device_id,
        &payload,
        effective_scope,
    )
}
