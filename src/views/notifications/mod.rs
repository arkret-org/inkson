//! Notifications panel - feed projection, hydration, and the
//! invite-accept flow.
//!
//! Purely structural module split; the external paths
//! `crate::views::notifications::*` stay identical via the re-exports
//! below:
//!   * [`model`]   — data types plus the pure projection / hydration / value helpers.
//!   * [`actions`] — the network-driven handlers (refresh, mark-all-read, invite accept).
//!   * [`panel`]   — the `NotificationsPanel` RSX component.

mod actions;
mod model;
mod panel;

#[cfg(test)]
mod tests;

// Crate-internal projection helpers consumed by `app.rs`,
// `sync_engine.rs` and the dashboard via `crate::views::notifications::*`.
pub(crate) use model::{
    default_notification_title, is_notification_account_data, merge_invite_notifications,
    notification_items_from_value, notification_value_read_by_cursor,
    realm_title_hints_from_values, value_string,
};
pub use panel::NotificationsPanel;
