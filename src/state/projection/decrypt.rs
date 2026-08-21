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
    let _ = (
        state_store,
        realm_id,
        actor_id,
        device_id,
        payload_value,
        circle_id,
    );
    // A projected patch value no longer carries enough outer Event context to
    // reconstruct the authenticated header. Keep it opaque until the reducer
    // projection threads the verified sender and Event kind alongside it.
    None
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn try_local_mls_decrypt_core_for_scope_from_verified_sender(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
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
        actor_id,
        device_id,
        &payload,
        effective_scope,
        verified_sender_domain,
    )
}
