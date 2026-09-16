//! Pure derivations behind the settings panel.
//!
//! `SettingsPanel` computed each of these inline, between its `use_signal`
//! declarations and its `rsx!`. None of them touches a Signal, so keeping them
//! there meant the only way to exercise a nav-search miss, an expired presence
//! preference or a do-not-disturb rehydration was to render the whole 2,600
//! line component. They take plain data and return plain data.

use arkret_sdk::PresencePreference;
use chrono::{DateTime, Utc};

use super::sections::{SETTINGS_NAV_GROUPS, SettingsSection};
use crate::notification_rules::DndSettings;

/// One rendered cluster of the settings sidebar: its group label key and the
/// sections that survived the search filter.
///
/// `SETTINGS_NAV_GROUPS` also carries a `*.hint` key per group, but no surface
/// renders it. It is left in the taxonomy rather than carried here, so this
/// struct describes what is actually drawn.
pub(super) struct SettingsNavGroup {
    pub label_key: &'static str,
    pub sections: Vec<SettingsSection>,
}

/// Sidebar groups that match `query`, with empty groups dropped.
///
/// `query` is matched against the *localized* section label, so the search box
/// finds a section by the name the reader can actually see. An empty query
/// shows everything (design/settings-ia-reorg.md §3.4).
pub(super) fn visible_nav_groups(query: &str) -> Vec<SettingsNavGroup> {
    let query = query.trim().to_lowercase();
    SETTINGS_NAV_GROUPS
        .iter()
        .copied()
        .filter_map(|(label_key, _hint_key, sections)| {
            let sections: Vec<SettingsSection> = sections
                .iter()
                .copied()
                .filter(|section| {
                    query.is_empty() || section.label().to_lowercase().contains(&query)
                })
                .collect();
            (!sections.is_empty()).then_some(SettingsNavGroup {
                label_key,
                sections,
            })
        })
        .collect()
}

/// Seed for the manual-presence editor (profiles-presence.md §3.6).
pub(super) struct PresenceEditorSeed {
    pub manual_state: String,
    pub status_message: String,
}

/// An expired preference seeds an empty editor rather than re-offering a
/// manual state the server has already stopped honouring.
pub(super) fn presence_editor_seed(
    preference: &PresencePreference,
    now: DateTime<Utc>,
) -> PresenceEditorSeed {
    if !preference.is_empty() && !preference.is_active(now) {
        return PresenceEditorSeed {
            manual_state: "auto".to_owned(),
            status_message: String::new(),
        };
    }
    PresenceEditorSeed {
        manual_state: preference
            .manual_state
            .map(arkret_sdk::ManualPresenceState::as_wire)
            .unwrap_or("auto")
            .to_owned(),
        status_message: preference.status_message.clone().unwrap_or_default(),
    }
}

/// Seed for the do-not-disturb toggle and mode picker.
pub(super) struct DndEditorSeed {
    pub enabled: bool,
    pub mode: String,
}

/// Rehydrates from the persisted snapshot instead of always rendering "off".
/// The saved body only carries a full-day period when the user picked "now",
/// so an enabled setting with no periods is still mode `off`.
pub(super) fn dnd_editor_seed(settings: Option<&DndSettings>) -> DndEditorSeed {
    let enabled = settings.is_some_and(|dnd| dnd.enabled);
    let mode = if settings.is_some_and(|dnd| dnd.enabled && !dnd.schedule.periods.is_empty()) {
        "now"
    } else {
        "off"
    };
    DndEditorSeed {
        enabled,
        mode: mode.to_owned(),
    }
}

/// Identity strings for the account section header.
pub(super) struct SessionIdentityLabels {
    pub principal: String,
    pub device: String,
    pub handles_label: String,
    pub handles_title: String,
}

pub(super) fn session_identity_labels(
    has_session: bool,
    principal_id: &str,
    device_id: &str,
    personal_handles: &[String],
    personal_handles_status: &str,
) -> SessionIdentityLabels {
    let handles_label =
        crate::views::helpers::account_handles_display(personal_handles, personal_handles_status);
    SessionIdentityLabels {
        principal: if has_session {
            principal_id.to_owned()
        } else {
            crate::i18n::tr("account.not_signed_in")
        },
        device: if has_session {
            device_id.to_owned()
        } else {
            crate::i18n::tr("settings.account.no_device_session")
        },
        handles_title: if personal_handles.is_empty() {
            handles_label.clone()
        } else {
            personal_handles.join(", ")
        },
        handles_label,
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
