use dioxus::prelude::*;
use serde_json::Value;

use crate::local_state::LocalStateStore;

/// Attempt a local MLS decrypt of an encrypted message-content JSON object
/// emitted by chat.rs
/// Send Secure. Returns `Some(plaintext_bytes)` on successful decrypt,
/// `None` for every soft failure (no snapshot, snapshot can't be
/// hydrated with this device's snapshot secret, payload doesn't
/// deserialize as a typed `EncryptedPayload`, group rejects the payload).
///
/// The caller — the `ck.audit.accessed` emitter inside
/// [`super::panel::TimelinePanel`] — uses `Some(...)` as the firing trigger, so any
/// soft failure quietly suppresses the audit emit instead of looping.
/// Runs on every target now that OpenMLS builds on wasm32 (the browser
/// uses the same in-tree OpenMLS via the `js` feature). Any soft failure
/// (no snapshot / wrong device secret / payload that doesn't decrypt)
/// returns `None`, so the audit emitter is a no-op in those cases.
///
/// The snapshot secret is device-scoped and read from `SecureKeyStore`.
/// Only real SDK-encrypted payloads should trigger the audit hook.
pub(super) fn try_local_mls_decrypt(
    state_store: Signal<LocalStateStore>,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload_value: &Value,
) -> Option<Vec<u8>> {
    try_local_mls_decrypt_core(
        &state_store.read(),
        realm_id,
        actor_id,
        device_id,
        payload_value,
    )
}

/// Shared MLS decrypt core used by the timeline audit emitter
/// (`try_local_mls_decrypt`, which holds a `Signal<LocalStateStore>`), the
/// chat decrypt-on-read path and the kanban decrypt-on-read path (which
/// already hold a borrowed `&LocalStateStore`).
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
