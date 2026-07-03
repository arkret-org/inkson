use serde_json::Value;

use crate::local_state::LocalStateStore;

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
pub(crate) fn try_local_mls_decrypt_core(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload_value: &Value,
) -> Option<Vec<u8>> {
    let payload: cokret_sdk::EncryptedPayload =
        serde_json::from_value(payload_value.clone()).ok()?;
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    crate::mls::runtime::decrypt_application_payload(
        state_store,
        secure_store.as_ref(),
        realm_id,
        actor_id,
        device_id,
        &payload,
    )
}
