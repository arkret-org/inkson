//! "Pending N" badge for the offline queue (P3B.5.3).
//!
//! Reads [`crate::offline::pending_count`] each render and surfaces a
//! small pill next to the connection status indicator. The badge is
//! hidden when the queue is empty.

use dioxus::prelude::*;

/// Props for the offline-pending badge. The parent should call
/// [`OfflinePendingBadge`] inside the topbar / sidebar shell and
/// thread a live `Signal<usize>` that the app shell updates whenever
/// the network state changes or a write enqueues.
#[derive(Clone, PartialEq, Props)]
pub struct OfflinePendingBadgeProps {
    pub pending: Signal<usize>,
}

#[component]
pub fn OfflinePendingBadge(props: OfflinePendingBadgeProps) -> Element {
    let count = *props.pending.read();
    if count == 0 {
        return rsx! {};
    }
    rsx! {
        span {
            class: "badge offline-pending-badge amber",
            "data-testid": "offline-pending-badge",
            "data-pending-count": "{count}",
            title: "Pending writes — will be sent when the network is healthy.",
            role: "status",
            "aria-live": "polite",
            "aria-label": "{count} pending offline writes",
            "Pending {count}"
        }
    }
}
