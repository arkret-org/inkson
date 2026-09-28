//! Notifications panel - feed projection, hydration, and the
//! invite-accept flow.
//!
//! Purely structural module split; the external paths
//! `crate::views::notifications::*` stay identical via the re-exports
//! below:
//!   * [`model`]   — data types plus the pure projection / hydration / value helpers.
//!   * [`actions`] — the network-driven handlers (refresh, mark-all-read, invite accept).
//!   * [`panel`]   — the `NotificationsPanel` RSX component.
//!   * [`invite_preview`] — the pre-accept Realm preview on invite cards.

mod actions;
mod invite_preview;
mod model;
mod panel;

#[cfg(test)]
mod tests;

// Crate-internal projection helpers consumed by the dashboard card and
// `app::sidebar` via `crate::views::notifications::*`. The notification /
// invite projection reducer lives in `projection::notifications` and is
// consumed there directly by the sync layer.
pub(crate) use model::{
    default_notification_title, notification_blocklist_suppressed,
    notification_value_read_by_cursor, notification_wire_state,
};
pub use panel::NotificationsPanel;
