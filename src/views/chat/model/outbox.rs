// Offline send outbox for the discussion composer.
//
// When the browser is offline, a `ak.message.create` send is parked here
// instead of failing. The queue is persisted to `localStorage` so a
// reload mid-outage keeps the unsent messages; on reconnect the chat view
// drains the queue and resubmits each entry through the normal send path.
//
// Spec: sync/client-sync.md offline-conflict handling — the client keeps a
// durable local intent and replays it once connectivity returns. Entries
// carry the stable local `ak:message:` id so replay is idempotent against
// the reducer's `ak.message.create` de-dup.

use super::*;

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
    /// Structured mentions already resolved by the picker. Older v1
    /// outbox rows predate this field, so they deserialize as empty and
    /// retain their original plain-text replay behavior.
    #[serde(default)]
    pub(crate) mentions: Vec<MentionNode>,
    /// Canonical controller handle captured when an offline `@me/<slug>`
    /// intent is queued. It is used only to expand the local `@me` alias
    /// before the replayed message is submitted.
    #[serde(default)]
    pub(crate) own_controller_handle: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_v1_outbox_rows_default_new_mention_fields() {
        let row: OutboxMessage = serde_json::from_value(json!({
            "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
            "strand_id": "ak:strand:0196419b-0000-7000-8000-000000000001",
            "channel_kind": "discussion",
            "message_id": "ak:message:0196419b-0000-7000-8000-000000000002",
            "body": "hello",
            "reply_to": null
        }))
        .expect("legacy outbox row");

        assert!(row.mentions.is_empty());
        assert!(row.own_controller_handle.is_none());
    }
}
