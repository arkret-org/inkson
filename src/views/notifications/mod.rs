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

// Crate-internal projection helpers consumed by the dashboard card and
// `app::sidebar` via `crate::views::notifications::*`. The notification /
// invite wire-payload projection primitives (`notification_items_from_value`,
// `is_notification_account_data`, `merge_invite_notifications`,
// `realm_title_hints_from_values`) moved to `projection::notifications`
// (YGN-ARCH-01) and are consumed there directly by the sync layer.
pub(crate) use model::{
    default_notification_title, notification_value_read_by_cursor, value_string,
};
pub use panel::NotificationsPanel;
