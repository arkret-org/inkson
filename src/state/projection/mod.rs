//! Sync projection layer (pure move from
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

pub use model::ProjectionEvent;
pub use sync::projection_events_from_sync_realms;

// Message / kanban raw-operation extraction (moved from the chat / kanban
// view models; see `message_ops` / `kanban_ops`).
pub(crate) mod kanban_ops;
pub(crate) mod message_ops;
pub(crate) mod moderation_ops;
