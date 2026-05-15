//! Write state badge — unified offline / optimistic / accepted / conflict states.
//!
//! The yougen client surfaces the same write lifecycle in Board, Card, and
//! Room views. `views/kanban.rs` originally defined its own `CardState`; this
//! module pulls the same semantics into a shared component for chat / forum /
//! timeline reuse, preventing drift across the three call sites.
//!
//! Spec sources:
//! - `sync/operations-sync.md`: offline-first writes; the Event Envelope is
//!   the source of truth.
//! - `authz/event-auth-state-resolution.md`: reducer rejections fall into
//!   `state_mismatch` or `cas_conflict`.
//! - `governance/content-moderation.md`: quarantined writes remain visible
//!   but flow through the moderation queue.
//!
//! State machine:
//! ```text
//! Optimistic → Queued → Submitted → Accepted | SoftFailed | CasConflict | Quarantined
//!                                                                    ↑
//!                                                         (Accepted ⇒ Synced)
//! ```

use dioxus::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteState {
    /// Aligned with the sync frontier — accepted by the server reducer.
    Synced,
    /// Applied optimistically on the client; not yet submitted.
    Optimistic,
    /// Sitting in the local offline queue, waiting for the network.
    Queued,
    /// Submitted to the Principal Server; awaiting acknowledgement.
    Submitted,
    /// Reducer accepted — equivalent to `Synced` but kept separate so the
    /// activity stream can render the moment of acceptance.
    Accepted,
    /// Reducer soft failure (schema / capability passed but the transition
    /// is illegal).
    SoftFailed,
    /// CAS / position-edge conflict (concurrent `cx.flow.move`).
    CasConflict,
    /// Capability check passed but the write is quarantined by moderation
    /// policy.
    Quarantined,
}

impl WriteState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Optimistic => "optimistic",
            Self::Queued => "queued",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::SoftFailed => "soft failed",
            Self::CasConflict => "CAS conflict",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn class_name(self) -> &'static str {
        match self {
            Self::Synced | Self::Accepted => "badge green",
            Self::Optimistic | Self::Queued | Self::Submitted => "badge blue",
            Self::SoftFailed | Self::CasConflict => "badge red",
            Self::Quarantined => "badge amber",
        }
    }

    /// One-line explanation of the state, suitable for tooltips / inbox
    /// summaries.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Synced => "Aligned with the sync frontier; reducer has accepted.",
            Self::Optimistic => "Applied optimistically on the client; not yet queued.",
            Self::Queued => "Queued in the local offline buffer, waiting for the network.",
            Self::Submitted => "Submitted to the Principal Server; awaiting acknowledgement.",
            Self::Accepted => "Reducer accepted; local state has been merged.",
            Self::SoftFailed => {
                "Reducer rejected (schema passed but the transition is illegal); rewritable."
            }
            Self::CasConflict => {
                "Concurrent write superseded by a later HLC; retained in the audit log for recovery."
            }
            Self::Quarantined => {
                "Capability check passed but moderation isolated the write into the review queue."
            }
        }
    }

    /// All variants, ordered the way the UI prefers to display them.
    pub fn all() -> [Self; 8] {
        [
            Self::Synced,
            Self::Optimistic,
            Self::Queued,
            Self::Submitted,
            Self::Accepted,
            Self::SoftFailed,
            Self::CasConflict,
            Self::Quarantined,
        ]
    }
}

/// A single pill-shaped write-state marker, suitable for KanbanCard,
/// Message, or Flow row decorations.
#[component]
pub fn WriteStatePill(state: String) -> Element {
    let parsed = parse_write_state(&state);
    let class = parsed.map(WriteState::class_name).unwrap_or("badge");
    let label = parsed.map(WriteState::label).unwrap_or(state.as_str());
    rsx! {
        span {
            class: "{class}",
            "data-testid": "write-state-pill",
            "title": "sync/operations-sync.md — write-plane state machine",
            "{label}"
        }
    }
}

/// Detailed explainer card, used in the audit / debug drawer.
#[component]
pub fn WriteStateExplainer(state: String) -> Element {
    let parsed = parse_write_state(&state);
    let class = parsed.map(WriteState::class_name).unwrap_or("badge");
    let label = parsed.map(WriteState::label).unwrap_or(state.as_str());
    let explanation = parsed
        .map(WriteState::explanation)
        .unwrap_or("unknown state");
    rsx! {
        div {
            class: "event",
            "data-testid": "write-state-explainer",
            div { class: "event-head", span { "Write state" } span { class: "{class}", "{label}" } }
            div { class: "muted", "{explanation}" }
        }
    }
}

fn parse_write_state(s: &str) -> Option<WriteState> {
    match s {
        "synced" => Some(WriteState::Synced),
        "optimistic" => Some(WriteState::Optimistic),
        "queued" => Some(WriteState::Queued),
        "submitted" => Some(WriteState::Submitted),
        "accepted" => Some(WriteState::Accepted),
        "soft failed" => Some(WriteState::SoftFailed),
        "CAS conflict" => Some(WriteState::CasConflict),
        "quarantined" => Some(WriteState::Quarantined),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_state_labels_are_unique() {
        let mut labels: Vec<&str> = WriteState::all().iter().map(|s| s.label()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(
            labels.len(),
            8,
            "every WriteState variant must have a unique label"
        );
    }

    #[test]
    fn write_state_classes_partition_by_severity() {
        // green = success states
        assert_eq!(WriteState::Synced.class_name(), "badge green");
        assert_eq!(WriteState::Accepted.class_name(), "badge green");
        // blue = in-flight
        assert_eq!(WriteState::Optimistic.class_name(), "badge blue");
        assert_eq!(WriteState::Queued.class_name(), "badge blue");
        assert_eq!(WriteState::Submitted.class_name(), "badge blue");
        // red = hard reject
        assert_eq!(WriteState::SoftFailed.class_name(), "badge red");
        assert_eq!(WriteState::CasConflict.class_name(), "badge red");
        // amber = soft / requires moderation review
        assert_eq!(WriteState::Quarantined.class_name(), "badge amber");
    }

    #[test]
    fn write_state_parses_display_label_strings() {
        assert_eq!(
            parse_write_state("CAS conflict"),
            Some(WriteState::CasConflict)
        );
        assert_eq!(
            parse_write_state("soft failed"),
            Some(WriteState::SoftFailed)
        );
        assert_eq!(parse_write_state("synced"), Some(WriteState::Synced));
        assert_eq!(parse_write_state("garbage"), None);
    }
}
