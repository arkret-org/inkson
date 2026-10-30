//! Write state badge — unified offline / optimistic / accepted / conflict states.
//!
//! The inkson client surfaces the same write lifecycle in Board, Card, and
//! Room views. `views/kanban.rs` originally defined its own `CardState`; this
//! module pulls the same semantics into a shared component for chat / forum /
//! Board reuse, preventing drift across the three call sites.
//!
//! Spec sources:
//! - `sync/operations-sync.md`: offline-first writes; the Event Envelope is the source of truth.
//! - `sync/authority-commit-log.md`: only the exact Event's covering RealmCommit confirms
//!   admission.
//! - `governance/content-moderation.md`: quarantined writes remain visible but flow through the
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteState {
    /// The accepted write is reflected in the local current projection.
    Synced,
    /// Applied optimistically on the client; not yet submitted.
    Optimistic,
    /// Sitting in the local offline queue, waiting for the network.
    Queued,
    /// Submitted to the Station; awaiting acknowledgement.
    Submitted,
    /// The exact Event has a verified covering RealmCommit; its local current
    /// projection may still be catching up.
    Accepted,
    /// The submission was refused, or a local submission attempt failed.
    SoftFailed,
    /// A write precondition failed (for example a product-level CAS guard).
    CasConflict,
    /// Capability check passed but the write is quarantined by moderation
    /// policy.
    Quarantined,
}

impl WriteState {
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
            },
            Self::Optimistic => WriteStateIconSpec {
                class_suffix: "is-optimistic",
            },
            Self::Queued => WriteStateIconSpec {
                class_suffix: "is-queued",
            },
            Self::Submitted => WriteStateIconSpec {
                class_suffix: "is-submitted",
            },
            Self::Accepted => WriteStateIconSpec {
                class_suffix: "is-accepted",
            },
            Self::SoftFailed => WriteStateIconSpec {
                class_suffix: "is-soft-failed",
            },
            Self::CasConflict => WriteStateIconSpec {
                class_suffix: "is-conflict",
            },
            Self::Quarantined => WriteStateIconSpec {
                class_suffix: "is-quarantined",
            },
        }
    }

    pub fn icon_class(self) -> String {
        let icon = self.icon();
        format!("write-state-icon {}", icon.class_suffix)
    }

    /// Interpret holder-local progress written by the durable outbound engine
    /// or accepted-current ingestion. These tags are presentation metadata,
    /// never wire evidence: their producers verify the exact Event/Commit pair
    /// before recording accepted, and current ingestion records synced.
    pub fn from_local_state(s: &str) -> Option<Self> {
        match s {
            "synced" => Some(Self::Synced),
            "optimistic" => Some(Self::Optimistic),
            "queued" => Some(Self::Queued),
            "submitting"
            | "forwarding"
            | "submitted"
            | "pending"
            | "pending_commit"
            | "pending_mls_binding" => Some(Self::Submitted),
            "accepted" | "committed" | "effective" => Some(Self::Accepted),
            "failed" | "rejected" | "soft_failed" | "cancelled" | "dropped" => {
                Some(Self::SoftFailed)
            }
            "conflict" | "cas_conflict" => Some(Self::CasConflict),
            "quarantined" => Some(Self::Quarantined),
            _ => None,
        }
    }

    pub fn localized_label(self) -> String {
        crate::i18n::tr(&format!("write_state.{}.label", self.data_state()))
    }

    pub fn localized_explanation(self) -> String {
        crate::i18n::tr(&format!("write_state.{}.description", self.data_state()))
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

/// Shared lifecycle badge for card and other write surfaces.
#[component]
pub fn WriteStateBadge(state: WriteState, icon_only: Option<bool>) -> Element {
    let class_name = format!(
        "{} write-state-badge{}",
        state.class_name(),
        if icon_only.unwrap_or(false) {
            " is-icon-only"
        } else {
            ""
        }
    );
    let data_state = state.data_state();
    let label = state.localized_label();
    let title = state.localized_explanation();
    rsx! {
        span {
            class: "{class_name}",
            "data-testid": "write-state-badge",
            "data-write-state": "{data_state}",
            title: "{title}",
            WriteStateIcon { state }
            span { class: "write-state-label", "{label}" }
        }
    }
}

#[component]
pub fn WriteStateIcon(state: WriteState) -> Element {
    let icon_class = state.icon_class();
    let label = state.localized_explanation();
    rsx! {
        span {
            class: "{icon_class}",
            role: "img",
            "aria-label": "{label}",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_state_tags_are_unique() {
        let mut labels: Vec<&str> = WriteState::all().iter().map(|s| s.data_state()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(
            labels.len(),
            8,
            "every WriteState variant must have a unique local tag"
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
    fn pending_local_progress_never_claims_acceptance() {
        for tag in [
            "submitting",
            "forwarding",
            "submitted",
            "pending",
            "pending_commit",
            "pending_mls_binding",
        ] {
            assert_eq!(
                WriteState::from_local_state(tag),
                Some(WriteState::Submitted),
                "{tag}"
            );
        }
        assert_eq!(WriteState::from_local_state("pending_seal"), None);
        assert_eq!(WriteState::from_local_state("garbage"), None);
    }
}
