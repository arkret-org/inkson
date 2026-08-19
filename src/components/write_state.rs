//! Write state badge — unified offline / optimistic / accepted / conflict states.
//!
//! The inkson client surfaces the same write lifecycle in Board, Card, and
//! Room views. `views/kanban.rs` originally defined its own `CardState`; this
//! module pulls the same semantics into a shared component for chat / forum /
//! Board reuse, preventing drift across the three call sites.
//!
//! Spec sources:
//! - `sync/operations-sync.md`: offline-first writes; the Event Envelope is the source of truth.
//! - `authz/event-auth-state-resolution.md`: reducer rejections fall into `state_mismatch` or
//!   `cas_conflict`.
//! - `governance/content-moderation.md`: quarantined writes remain visible but strand through the
//!   moderation queue.
//!
//! State machine:
//! ```text
//! Optimistic → Queued → Submitted → Accepted | SoftFailed | CasConflict | Quarantined
//!                                                                    ↑
//!                                                         (Accepted ⇒ Synced)
//! ```

use dioxus::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteStateIconSpec {
    pub class_suffix: &'static str,
    pub aria_label: &'static str,
}

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
    /// CAS / position-edge conflict (concurrent `ak.strand.move`).
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

    pub fn data_state(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Optimistic => "optimistic",
            Self::Queued => "queued",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::SoftFailed => "soft_failed",
            Self::CasConflict => "cas_conflict",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn icon(self) -> WriteStateIconSpec {
        match self {
            Self::Synced => WriteStateIconSpec {
                class_suffix: "is-synced",
                aria_label: "Synced",
            },
            Self::Optimistic => WriteStateIconSpec {
                class_suffix: "is-optimistic",
                aria_label: "Optimistic local write",
            },
            Self::Queued => WriteStateIconSpec {
                class_suffix: "is-queued",
                aria_label: "Queued local write",
            },
            Self::Submitted => WriteStateIconSpec {
                class_suffix: "is-submitted",
                aria_label: "Submitted write",
            },
            Self::Accepted => WriteStateIconSpec {
                class_suffix: "is-accepted",
                aria_label: "Accepted by server",
            },
            Self::SoftFailed => WriteStateIconSpec {
                class_suffix: "is-soft-failed",
                aria_label: "Write failed",
            },
            Self::CasConflict => WriteStateIconSpec {
                class_suffix: "is-conflict",
                aria_label: "CAS conflict",
            },
            Self::Quarantined => WriteStateIconSpec {
                class_suffix: "is-quarantined",
                aria_label: "Quarantined write",
            },
        }
    }

    pub fn icon_class(self) -> String {
        let icon = self.icon();
        format!("write-state-icon {}", icon.class_suffix)
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

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "synced" | "effective" => Some(Self::Synced),
            "optimistic" => Some(Self::Optimistic),
            "queued" => Some(Self::Queued),
            "submitted" => Some(Self::Submitted),
            "accepted" | "pending" | "pending_seal" => Some(Self::Accepted),
            "failed" | "rejected" | "soft_failed" | "soft failed" => Some(Self::SoftFailed),
            "conflict" | "cas_conflict" | "CAS conflict" => Some(Self::CasConflict),
            "quarantined" => Some(Self::Quarantined),
            _ => None,
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

#[component]
pub fn WriteStateIcon(state: WriteState) -> Element {
    let icon_class = state.icon_class();
    let icon = state.icon();
    rsx! {
        span {
            class: "{icon_class}",
            role: "img",
            "aria-label": "{icon.aria_label}",
        }
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
    fn write_state_icon_mapping_covers_every_variant() {
        let mut suffixes: Vec<&str> = WriteState::all()
            .iter()
            .map(|state| state.icon().class_suffix)
            .collect();
        suffixes.sort();
        suffixes.dedup();
        assert_eq!(suffixes.len(), 8);
    }

    #[test]
    fn write_state_parses_display_label_strings() {
        assert_eq!(
            WriteState::from_wire("CAS conflict"),
            Some(WriteState::CasConflict)
        );
        assert_eq!(
            WriteState::from_wire("soft failed"),
            Some(WriteState::SoftFailed)
        );
        assert_eq!(WriteState::from_wire("synced"), Some(WriteState::Synced));
        assert_eq!(WriteState::from_wire("garbage"), None);
    }
}
