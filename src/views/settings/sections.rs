//! Settings navigation taxonomy: the `SettingsSection` enum (one variant per
//! settings surface, with slug/label/route mapping), the `DiagnosticsMode`
//! sub-tab enum, and the nav-group consts that drive the settings sidebar.

use crate::routes::Route;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SettingsSection {
    Account,
    Agents,
    Server,
    Devices,
    Storage,
    Encryption,
    Recovery,
    Mimi,
    Notifications,
    Privacy,
    /// U4 invite_receive_policy (`/settings/invite-policy`).
    InvitePolicy,
    /// G3.Y3 — personal blocklist (`/settings/blocklist`).
    Blocklist,
    /// G3.Y3 — capability delegation viewer (`/settings/capabilities`).
    Capabilities,
    Theme,
    Release,
}

impl SettingsSection {
    pub(super) fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or("account") {
            "account" => Self::Account,
            "agents" => Self::Agents,
            "devices" => Self::Devices,
            "storage" => Self::Storage,
            "encryption" => Self::Encryption,
            "security" | "key-backup" | "recovery" => Self::Recovery,
            "mimi" => Self::Mimi,
            "push" | "notifications" => Self::Notifications,
            "privacy" => Self::Privacy,
            "invite-policy" | "invite_policy" => Self::InvitePolicy,
            "blocklist" | "blocked-users" => Self::Blocklist,
            "capabilities" => Self::Capabilities,
            "audit" | "audit-log" | "developer" | "developer-tools" | "release" => Self::Release,
            "theme" => Self::Theme,
            _ => Self::Server,
        }
    }

    pub(super) fn slug(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Agents => "agents",
            Self::Server => "server",
            Self::Devices => "devices",
            Self::Storage => "storage",
            Self::Encryption => "encryption",
            Self::Recovery => "recovery",
            Self::Mimi => "mimi",
            Self::Notifications => "notifications",
            Self::Privacy => "privacy",
            Self::InvitePolicy => "invite-policy",
            Self::Blocklist => "blocklist",
            Self::Capabilities => "capabilities",
            Self::Theme => "theme",
            Self::Release => "release",
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Account => "Account information",
            Self::Agents => "My Agents",
            Self::Server => "Server information",
            Self::Devices => "Devices",
            Self::Storage => "Data & sync",
            Self::Encryption => "Security",
            Self::Recovery => "Recovery",
            Self::Mimi => "Integrations",
            Self::Notifications => "Notifications",
            Self::Privacy => "Privacy & sharing",
            Self::InvitePolicy => "Who can invite me",
            Self::Blocklist => "Blocked actors",
            Self::Capabilities => "Capabilities",
            Self::Theme => "Appearance & locale",
            Self::Release => "Diagnostics",
        }
    }

    pub(super) fn route(self) -> Route {
        match self {
            Self::Devices => Route::SettingsDevices,
            Self::Recovery => Route::SettingsRecovery,
            _ => Route::SettingsSection {
                section: self.slug().to_owned(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DiagnosticsMode {
    Developer,
    Audit,
}

impl DiagnosticsMode {
    pub(super) fn from_slug(slug: Option<&str>) -> Option<Self> {
        match slug {
            Some("developer" | "developer-tools") => Some(Self::Developer),
            Some("audit" | "audit-log") => Some(Self::Audit),
            _ => None,
        }
    }

    pub(super) fn slug(self) -> &'static str {
        match self {
            Self::Developer => "developer",
            Self::Audit => "audit",
        }
    }

    pub(super) fn route(self) -> Route {
        Route::SettingsSection {
            section: self.slug().to_owned(),
        }
    }
}

pub(super) const SETTINGS_ACCOUNT_GROUP: &[SettingsSection] = &[
    SettingsSection::Account,
    SettingsSection::Agents,
    SettingsSection::Server,
    SettingsSection::Devices,
    SettingsSection::Recovery,
];
pub(super) const SETTINGS_DELIVERY_GROUP: &[SettingsSection] = &[
    SettingsSection::Notifications,
    SettingsSection::Privacy,
    // U4 invite_receive_policy is an actor-private
    // disclosure control, so it sits with the other privacy surfaces.
    SettingsSection::InvitePolicy,
    // G3.Y3 blocklist sits next to Privacy because it is an actor-private
    // disclosure control (spec governance/content-moderation.md §4).
    SettingsSection::Blocklist,
];
pub(super) const SETTINGS_CLIENT_GROUP: &[SettingsSection] = &[SettingsSection::Theme];
pub(super) const SETTINGS_ADVANCED_GROUP: &[SettingsSection] = &[
    SettingsSection::Capabilities,
    SettingsSection::Storage,
    SettingsSection::Release,
];
pub(super) const SETTINGS_NAV_GROUPS: &[(&str, &str, &[SettingsSection])] = &[
    (
        "Account",
        "Identity, server, and signed-in devices.",
        SETTINGS_ACCOUNT_GROUP,
    ),
    (
        "Notifications & privacy",
        "Notification delivery behavior and actor-private disclosure controls.",
        SETTINGS_DELIVERY_GROUP,
    ),
    ("App", "Appearance and locale.", SETTINGS_CLIENT_GROUP),
    (
        "Advanced",
        "Capability, storage, and protocol diagnostics.",
        SETTINGS_ADVANCED_GROUP,
    ),
];
