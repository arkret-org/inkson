// Offline send outbox for the discussion composer.
//
// When the browser is offline, a `ck.message.create` send is parked here
// instead of failing. The queue is persisted to `localStorage` so a
// reload mid-outage keeps the unsent messages; on reconnect the chat view
// drains the queue and resubmits each entry through the normal send path.
//
// Spec: sync/client-sync.md offline-conflict handling — the client keeps a
// durable local intent and replays it once connectivity returns. Entries
// carry the stable local `ak:message:` id so replay is idempotent against
// the reducer's `ck.message.create` de-dup.

/// A single parked outgoing message awaiting connectivity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OutboxMessage {
    pub(crate) realm_id: String,
    pub(crate) strand_id: String,
    pub(crate) channel_kind: String,
    /// Stable local `ak:message:` id; reused as the durable message id so
    /// a replayed send collapses with the optimistic local row.
    pub(crate) message_id: String,
    pub(crate) body: String,
    pub(crate) reply_to: Option<String>,
}

#[cfg(target_arch = "wasm32")]
fn storage_key(account_did: &str) -> String {
    format!("inkson.chat.outbox.v1::{account_did}")
}

/// Load the persisted outbox for `account_did`. Returns an empty vec when
/// nothing is stored or the blob is unreadable (best-effort; a corrupt
/// blob must not wedge the composer).
pub(crate) fn load_outbox(account_did: &str) -> Vec<OutboxMessage> {
    let _ = account_did;
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(storage) = crate::local_state::browser_storage()
            && let Ok(Some(raw)) = storage.get_item(&storage_key(account_did))
            && let Ok(parsed) = serde_json::from_str::<Vec<OutboxMessage>>(&raw)
        {
            return parsed;
        }
    }
    Vec::new()
}

/// Persist `entries` for `account_did`. No-op off-wasm and on storage
/// failure (private-mode / quota); the in-memory signal stays authoritative
/// for the current session.
pub(crate) fn save_outbox(account_did: &str, entries: &[OutboxMessage]) {
    let _ = (account_did, entries);
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(storage) = crate::local_state::browser_storage()
            && let Ok(raw) = serde_json::to_string(entries)
        {
            let _ = storage.set_item(&storage_key(account_did), &raw);
        }
    }
}

/// Read `navigator.onLine`. Defaults to `true` off-wasm and when the
/// navigator is unavailable so non-browser builds never block sends.
pub(crate) fn navigator_online() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window()
            .map(|window| window.navigator().on_line())
            .unwrap_or(true);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        true
    }
}
