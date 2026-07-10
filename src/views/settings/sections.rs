//! Settings navigation taxonomy: the `SettingsSection` enum (one variant per
//! settings surface, with slug/label/route mapping) and the nav-group consts
//! that drive the settings sidebar.

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
    /// TSP connections (`/settings/connections`) — interop extension profile.
    Connections,
    Notifications,
    Privacy,
    /// U4 invite_receive_policy (`/settings/invite-policy`).
    InvitePolicy,
    /// Holder-private consent surface (`/settings/consent`).
    Consent,
    /// G3.Y3 — personal blocklist (`/settings/blocklist`).
    Blocklist,
    /// G3.Y3 — capability delegation viewer (`/settings/capabilities`).
    Capabilities,
    Theme,
    Release,
    /// Read-only audit-event inspector (`/audit`), promoted from the
    /// Release diagnostics sub-tab to a first-class section.
    Audit,
    /// Developer tools / protocol diagnostics (`/developer`), promoted
    /// from the Release diagnostics sub-tab to a first-class section.
    Developer,
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
            "connections" | "tsp" => Self::Connections,
            "push" | "notifications" => Self::Notifications,
            "privacy" => Self::Privacy,
            "invite-policy" | "invite_policy" => Self::InvitePolicy,
            "consent" => Self::Consent,
            "blocklist" | "blocked-users" => Self::Blocklist,
            "capabilities" => Self::Capabilities,
            "audit" | "audit-log" => Self::Audit,
            "developer" | "developer-tools" => Self::Developer,
            "release" => Self::Release,
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
            Self::Connections => "connections",
            Self::Notifications => "notifications",
            Self::Privacy => "privacy",
            Self::InvitePolicy => "invite-policy",
            Self::Consent => "consent",
            Self::Blocklist => "blocklist",
            Self::Capabilities => "capabilities",
            Self::Theme => "theme",
            Self::Release => "release",
            Self::Audit => "audit",
            Self::Developer => "developer",
        }
    }

    /// i18n key for the section label. Render sites resolve it through
    /// [`crate::i18n::tr`]; terminology was humanised here (TSP
    /// connections → External connections, Capabilities → App
    /// authorizations, Blocked actors → Block list, Consent → Invites &
    /// consent, Diagnostics → Release status).
    pub(super) fn label_key(self) -> &'static str {
        match self {
            Self::Account => "settings.section.account",
            Self::Agents => "settings.section.agents",
            Self::Server => "settings.section.server",
            Self::Devices => "settings.section.devices",
            Self::Storage => "settings.section.storage",
            Self::Encryption => "settings.section.encryption",
            Self::Recovery => "settings.section.recovery",
            Self::Mimi => "settings.section.mimi",
            Self::Connections => "settings.section.connections",
            Self::Notifications => "settings.section.notifications",
            Self::Privacy => "settings.section.privacy",
            Self::InvitePolicy => "settings.section.invite_policy",
            Self::Consent => "settings.section.consent",
            Self::Blocklist => "settings.section.blocklist",
            Self::Capabilities => "settings.section.capabilities",
            Self::Theme => "settings.section.theme",
            Self::Release => "settings.section.release",
            Self::Audit => "settings.section.audit",
            Self::Developer => "settings.section.developer",
        }
    }

    /// Resolve the section label in the active locale.
    pub(super) fn label(self) -> String {
        crate::i18n::tr(self.label_key())
    }

    pub(super) fn route(self) -> Route {
        match self {
            Self::Devices => Route::SettingsDevices,
            Self::Recovery => Route::SettingsRecovery,
            Self::Audit => Route::Audit,
            Self::Developer => Route::Developer,
            _ => Route::SettingsSection {
                section: self.slug().to_owned(),
            },
        }
    }
}

// Six-group taxonomy (design/settings-ia-reorg.md §3.1): 账号 / 设备与安全 /
// 隐私 / 通知 / 外观与语言 / 高级. `Mimi` is intentionally absent from every
// group — the MIMI interop test surface stays reachable only by direct route
// so it does not leak into normal settings navigation (design §3.3).
pub(super) const SETTINGS_ACCOUNT_GROUP: &[SettingsSection] = &[
    SettingsSection::Account,
    SettingsSection::Agents,
    SettingsSection::Server,
];
pub(super) const SETTINGS_SECURITY_GROUP: &[SettingsSection] = &[
    SettingsSection::Devices,
    SettingsSection::Recovery,
    SettingsSection::Encryption,
    // Capability delegation ("App authorizations") is a device-scoped
    // security control, so it sits with devices/recovery.
    SettingsSection::Capabilities,
];
pub(super) const SETTINGS_PRIVACY_GROUP: &[SettingsSection] = &[
    SettingsSection::Privacy,
    // G3.Y3 blocklist is an actor-private disclosure control
    // (spec governance/content-moderation.md §4).
    SettingsSection::Blocklist,
    // U4 invite_receive_policy is an actor-private disclosure control.
    SettingsSection::InvitePolicy,
    // Holder-private consent decisions (spec identity/consent-model.md §2).
    SettingsSection::Consent,
];
pub(super) const SETTINGS_NOTIFICATIONS_GROUP: &[SettingsSection] =
    &[SettingsSection::Notifications];
pub(super) const SETTINGS_APPEARANCE_GROUP: &[SettingsSection] = &[SettingsSection::Theme];
// `Connections` (TSP) is intentionally absent from every group, like `Mimi`:
// the current page only records a local placeholder row and never performs
// the real `ak.service.tsp` bootstrap, so it must not present itself as a
// working setting. It stays reachable at `/settings/connections` for
// development until the live TSP flow lands.
pub(super) const SETTINGS_ADVANCED_GROUP: &[SettingsSection] = &[
    SettingsSection::Storage,
    SettingsSection::Release,
    SettingsSection::Audit,
    SettingsSection::Developer,
];
/// `(group_label_key, group_hint_key, sections)`. Both text slots are i18n
/// keys resolved through [`crate::i18n::tr`] at render time.
pub(super) const SETTINGS_NAV_GROUPS: &[(&str, &str, &[SettingsSection])] = &[
    (
        "settings.group.account",
        "settings.group.account.hint",
        SETTINGS_ACCOUNT_GROUP,
    ),
    (
        "settings.group.security",
        "settings.group.security.hint",
        SETTINGS_SECURITY_GROUP,
    ),
    (
        "settings.group.privacy",
        "settings.group.privacy.hint",
        SETTINGS_PRIVACY_GROUP,
    ),
    (
        "settings.group.notifications",
        "settings.group.notifications.hint",
        SETTINGS_NOTIFICATIONS_GROUP,
    ),
    (
        "settings.group.appearance",
        "settings.group.appearance.hint",
        SETTINGS_APPEARANCE_GROUP,
    ),
    (
        "settings.group.advanced",
        "settings.group.advanced.hint",
        SETTINGS_ADVANCED_GROUP,
    ),
];
