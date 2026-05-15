//! Unified four-state sync badge.
//!
//! Several views (`document.rs`, `recovery.rs`, settings backup) need to
//! tell the user whether a draft/payload is:
//!   * local-only (not yet pushed),
//!   * in flight,
//!   * confirmed by the server, or
//!   * last attempt failed.
//!
//! Before this module each view hand-rolled its own enum + `label()` +
//! `class()` pair. The strings drift over time and the CSS class
//! mapping has to be kept in sync by hand. This module is the single
//! source of truth: the badge state + colour mapping live here, and
//! callers may override the user-facing label per-context (e.g. "Local
//! draft" for documents vs "Local only" for recovery).
//!
//! `kanban.rs::CardState` is intentionally not unified into this — its
//! eight variants model the SDK's Move lifecycle (queued / submitted /
//! accepted / soft-failed / quarantined / CAS-conflict), which is a
//! richer vocabulary than "did upload succeed".

use dioxus::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncBadgeState {
    /// Authored locally; no upload attempted yet (or the user has
    /// explicitly declined to sync). Persists across reloads via the
    /// local store, but is invisible to other devices.
    Local,
    /// Upload is in progress.
    Pending,
    /// The server has confirmed the upload.
    Synced,
    /// Last upload attempt failed; the local copy is still authoritative
    /// and the user can retry.
    Failed,
}

impl SyncBadgeState {
    /// Default label for each state. Callers can override these via the
    /// `local_label` / `pending_label` / `synced_label` / `failed_label`
    /// props on [`SyncBadge`] when domain-specific copy reads better
    /// (e.g. "Uploading…" vs "Pending sync…").
    pub fn default_label(self) -> &'static str {
        match self {
            Self::Local => "Local only",
            Self::Pending => "Pending sync…",
            Self::Synced => "Synced",
            Self::Failed => "Sync failed",
        }
    }

    /// CSS class used by all three of the legacy hand-rolled enums; we
    /// keep the same colour mapping here so existing stylesheets keep
    /// working without changes.
    pub fn class_name(self) -> &'static str {
        match self {
            Self::Local => "badge",
            Self::Pending => "badge amber",
            Self::Synced => "badge green",
            Self::Failed => "badge red",
        }
    }
}

#[component]
pub fn SyncBadge(
    state: SyncBadgeState,
    /// Optional per-call override for the Local label (e.g. "Local
    /// draft"). When `None` the default from [`SyncBadgeState::default_label`]
    /// is used.
    local_label: Option<String>,
    pending_label: Option<String>,
    synced_label: Option<String>,
    failed_label: Option<String>,
    test_id: Option<String>,
) -> Element {
    let label = match state {
        SyncBadgeState::Local => local_label,
        SyncBadgeState::Pending => pending_label,
        SyncBadgeState::Synced => synced_label,
        SyncBadgeState::Failed => failed_label,
    }
    .unwrap_or_else(|| state.default_label().to_owned());
    let class = state.class_name();
    let testid = test_id.unwrap_or_else(|| "sync-badge".to_owned());
    rsx! {
        span {
            class: "{class}",
            "data-testid": "{testid}",
            "{label}"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_labels_are_distinct() {
        let states = [
            SyncBadgeState::Local,
            SyncBadgeState::Pending,
            SyncBadgeState::Synced,
            SyncBadgeState::Failed,
        ];
        let labels: Vec<_> = states.iter().map(|s| s.default_label()).collect();
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(
                    labels[i], labels[j],
                    "states {i} and {j} share a label — that defeats the badge"
                );
            }
        }
    }

    #[test]
    fn class_mapping_covers_every_variant() {
        for state in [
            SyncBadgeState::Local,
            SyncBadgeState::Pending,
            SyncBadgeState::Synced,
            SyncBadgeState::Failed,
        ] {
            assert!(state.class_name().starts_with("badge"));
        }
    }
}
