//! Sync projection layer (YGN-ARCH-01 step 3, pure move from
//! `views/account_projection`, zero behavior change): folds account-subscribe
//! / events-subscribe wire payloads into local projection models
//! ([`ProjectionEvent`], message / kanban `RawOperationRecord`s). Consumed by
//! `sync_engine` and the views; contains no RSX.

mod decrypt;
mod model;
pub(crate) mod notifications;
mod sync;

#[cfg(test)]
mod tests;

pub(crate) use decrypt::try_local_mls_decrypt_core;
pub use model::ProjectionEvent;
pub use sync::projection_events_from_sync_realms;

// Message / kanban raw-operation extraction (moved from the chat / kanban
// view models; see `message_ops` / `kanban_ops`).
pub(crate) mod kanban_ops;
pub(crate) mod message_ops;
pub(crate) mod moderation_ops;

/// First non-empty trimmed string at `path` under `value` (shared by the
/// projection extractors).
pub(crate) fn json_path_string(value: Option<&serde_json::Value>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
