use dioxus::prelude::*;
use dioxus_router::Routable;

use crate::views::View;

/// All navigable routes in the application.
/// Each variant maps to a URL path and a corresponding View.
#[derive(Clone, Debug, PartialEq, Routable)]
pub enum Route {
    #[route("/", crate::app::RouterView)]
    Dashboard,

    #[route("/login", crate::app::RouterView)]
    Login,

    #[route("/auth/callback", crate::app::RouterView)]
    AuthCallback,

    #[route("/timeline", crate::app::RouterView)]
    Timeline,

    #[route("/spaces/:space_id", SpacePage)]
    Space { space_id: String },

    #[route("/timeline/:space_id", TimelineSpacePage)]
    TimelineSpace { space_id: String },

    #[route("/timeline/:space_id/message/:message_id", TimelineMessagePage)]
    TimelineMessage {
        space_id: String,
        message_id: String,
    },

    #[route("/chat/:space_id", ChatSpacePage)]
    Chat { space_id: String },

    #[route("/directory", crate::app::RouterView)]
    Directory,

    #[route("/contacts", crate::app::RouterView)]
    Contacts,

    #[route("/contacts/new", crate::app::RouterView)]
    ContactsNew,

    #[route("/setup", crate::app::RouterView)]
    Setup,

    #[route("/setup/:section", SetupSectionPage)]
    SetupSection { section: String },

    #[route("/settings", crate::app::RouterView)]
    Settings,

    /// G3.Y1 — device management (list + revoke). Static segment so
    /// dioxus-router matches this before `/settings/:section` falls
    /// through to the generic `SettingsPanel`.
    #[route("/settings/devices", crate::app::RouterView)]
    SettingsDevices,

    /// G3.Y1 — QR-driven pairing for a sibling device. Live on its
    /// own URL so the e2e harness can deep-link into the pair flow
    /// without scrolling through the device list.
    #[route("/settings/devices/pair", crate::app::RouterView)]
    SettingsDevicesPair,

    /// G3.Y1 — recovery passphrase setup + confirmation. Distinct
    /// from the existing `Route::Recovery` (`/recovery`) which hosts
    /// the broader recovery-options aggregator; this one is the
    /// single-purpose passphrase ceremony surfaced from the settings
    /// sidebar.
    #[route("/settings/recovery", crate::app::RouterView)]
    SettingsRecovery,

    /// G3.Y1 — local key-backup status + manual trigger / restore
    /// buttons. Backed by soland's `cx.schema.key_backup.v1` endpoints
    /// (`PUT/GET /api/v1/keys/backups/{backup_id}`) plus the local MLS
    /// snapshot bookkeeping in `mls_persistence`.
    #[route("/settings/security", crate::app::RouterView)]
    SettingsSecurity,

    /// G3.Y1 — passphrase-driven restore on a fresh device. Sibling
    /// of [`Route::Recovery`] (`/recovery`) but targeted at the
    /// recover-from-backup case the cotest harness exercises against
    /// an empty browser context.
    #[route("/recover", crate::app::RouterView)]
    Recover,

    #[route("/settings/:section", SettingsSectionPage)]
    SettingsSection { section: String },

    #[route("/devices/verify", crate::app::RouterView)]
    VerifyDevice,

    #[route("/space/:space_id/admin", SpaceAdminPage)]
    SpaceAdmin { space_id: String },

    #[route("/space/:space_id/admin/:section", SpaceAdminSectionPage)]
    SpaceAdminSection { space_id: String, section: String },

    #[route("/audit", crate::app::RouterView)]
    Audit,

    /// T7.1 — Developer Tools / Diagnostics aggregator. Hosts the
    /// protocol-level details (schema ids, event kinds, raw event log,
    /// profile id, conformance) that used to leak into the main flow.
    #[route("/developer", crate::app::RouterView)]
    Developer,

    #[route("/kanban", crate::app::RouterView)]
    Kanban,

    #[route("/kanban/:space_id", KanbanSpacePage)]
    KanbanSpace { space_id: String },

    #[route("/kanban/:space_id/task/:task_id", KanbanTaskPage)]
    KanbanTask { space_id: String, task_id: String },

    #[route("/notifications", crate::app::RouterView)]
    Notifications,

    #[route("/notifications/settings", NotificationsSettingsPage)]
    NotificationsSettings,

    #[route("/document", crate::app::RouterView)]
    Document,

    #[route("/document/new", crate::app::RouterView)]
    DocumentNew,

    #[route("/document/:space_id", DocumentSpacePage)]
    DocumentSpace { space_id: String },

    #[route("/call", crate::app::RouterView)]
    Call,

    #[route("/recovery", crate::app::RouterView)]
    Recovery,

    #[route("/onboarding", crate::app::RouterView)]
    Onboarding,

    #[route("/quarantine", crate::app::RouterView)]
    Quarantine,

    #[route("/applets", crate::app::RouterView)]
    Applets,

    #[route("/agents", crate::app::RouterView)]
    Agents,

    /// A6.1 — global cross-Space message search. Triggered by Cmd+F
    /// (Ctrl+F on non-Mac), the topbar `topbar-search-button`, or by
    /// directly navigating to `/search`. Backed by soland's
    /// `POST /api/v1/index/search` substring scan.
    #[route("/search", crate::app::RouterView)]
    Search,
}

#[component]
fn TimelineSpacePage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn TimelineMessagePage(space_id: String, message_id: String) -> Element {
    let _ = (space_id, message_id);
    rsx! { crate::app::RouterView {} }
}

#[component]
fn ChatSpacePage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn SpacePage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn SettingsSectionPage(section: String) -> Element {
    let _ = section;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn SetupSectionPage(section: String) -> Element {
    let _ = section;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn SpaceAdminPage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn SpaceAdminSectionPage(space_id: String, section: String) -> Element {
    let _ = (space_id, section);
    rsx! { crate::app::RouterView {} }
}

#[component]
fn KanbanSpacePage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn KanbanTaskPage(space_id: String, task_id: String) -> Element {
    let _ = (space_id, task_id);
    rsx! { crate::app::RouterView {} }
}

#[component]
fn DocumentSpacePage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn NotificationsSettingsPage() -> Element {
    rsx! { crate::app::RouterView {} }
}

impl Route {
    /// Convert a Route to the corresponding View enum variant.
    pub fn to_view(&self) -> View {
        match self {
            Route::Dashboard => View::Dashboard,
            Route::Login | Route::AuthCallback => View::Login,
            Route::Space { .. } => View::Timeline,
            Route::Timeline | Route::TimelineSpace { .. } | Route::TimelineMessage { .. } => {
                View::Timeline
            }
            Route::Chat { .. } => View::Chat,
            Route::Contacts | Route::ContactsNew => View::Contacts,
            Route::Directory => View::Directory,
            Route::Setup | Route::SetupSection { .. } => View::Setup,
            Route::Settings | Route::SettingsSection { .. } | Route::NotificationsSettings => {
                View::Settings
            }
            // G3.Y1 — new device / recovery / security panels render
            // under the existing settings shell visually but are
            // distinct top-level View variants so the sidebar +
            // command-palette state machine can highlight them
            // individually.
            Route::SettingsDevices | Route::SettingsDevicesPair => View::SettingsDevices,
            Route::SettingsRecovery => View::SettingsRecovery,
            Route::SettingsSecurity => View::SettingsSecurity,
            Route::Recover => View::Recover,
            Route::VerifyDevice => View::VerifyDevice,
            Route::SpaceAdmin { .. } | Route::SpaceAdminSection { .. } => View::SpaceAdmin,
            // Audit / Call / Applets routes still render their own panels
            // (see `Route::Audit`/`Route::Call`/`Route::Applets` arms in
            // `app.rs`) but no longer have dedicated `View` enum variants —
            // the variants were unreferenced anywhere except this mapping,
            // and nothing in the UI dispatches on them. Map to Dashboard so
            // `view` signal stays consistent for sidebar / palette state.
            Route::Audit | Route::Call | Route::Applets | Route::Developer => View::Dashboard,
            Route::Kanban | Route::KanbanSpace { .. } | Route::KanbanTask { .. } => View::Kanban,
            Route::Notifications => View::Notifications,
            Route::Document | Route::DocumentNew | Route::DocumentSpace { .. } => View::Document,
            Route::Recovery => View::Recovery,
            Route::Onboarding => View::Onboarding,
            Route::Quarantine => View::Quarantine,
            Route::Agents => View::Agents,
            Route::Search => View::Search,
        }
    }

    /// Extract space_id from routes that carry one.
    pub fn space_id(&self) -> Option<&str> {
        match self {
            Route::Space { space_id }
            | Route::TimelineSpace { space_id }
            | Route::TimelineMessage { space_id, .. }
            | Route::Chat { space_id }
            | Route::KanbanSpace { space_id }
            | Route::KanbanTask { space_id, .. }
            | Route::SpaceAdmin { space_id }
            | Route::SpaceAdminSection { space_id, .. } => Some(space_id.as_str()),
            Route::DocumentSpace { space_id } if !space_id.starts_with("cx:morph:") => {
                Some(space_id.as_str())
            }
            _ => None,
        }
    }

    /// Extract setup section from routes that carry one.
    pub fn setup_section(&self) -> Option<&str> {
        match self {
            Route::SetupSection { section } => Some(section.as_str()),
            _ => None,
        }
    }

    /// Extract settings section from routes that carry one.
    pub fn settings_section(&self) -> Option<&str> {
        match self {
            Route::SettingsSection { section } => Some(section.as_str()),
            Route::NotificationsSettings => Some("notifications"),
            _ => None,
        }
    }

    /// Extract space admin section from routes that carry one.
    pub fn space_admin_section(&self) -> Option<&str> {
        match self {
            Route::SpaceAdminSection { section, .. } => Some(section.as_str()),
            _ => None,
        }
    }
}

/// Convert a View enum variant to the default Route for that view.
impl From<View> for Route {
    fn from(view: View) -> Self {
        match view {
            View::Dashboard => Route::Dashboard,
            View::Login => Route::Login,
            View::Timeline => Route::Timeline,
            View::Chat => Route::Chat {
                space_id: String::new(),
            },
            View::Contacts => Route::Contacts,
            View::Directory => Route::Directory,
            View::Setup => Route::Setup,
            View::Settings => Route::Settings,
            View::SettingsDevices => Route::SettingsDevices,
            View::SettingsRecovery => Route::SettingsRecovery,
            View::SettingsSecurity => Route::SettingsSecurity,
            View::Recover => Route::Recover,
            View::VerifyDevice => Route::VerifyDevice,
            View::SpaceAdmin => Route::SpaceAdmin {
                space_id: String::new(),
            },
            View::Kanban => Route::Kanban,
            View::Notifications => Route::Notifications,
            View::Document => Route::DocumentNew,
            View::Recovery => Route::Recovery,
            View::Onboarding => Route::Onboarding,
            View::Quarantine => Route::Quarantine,
            View::Agents => Route::Agents,
            View::Search => Route::Search,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_to_view_roundtrip() {
        let routes = vec![
            Route::Dashboard,
            Route::Login,
            Route::Space {
                space_id: "cx:space:roundtrip".to_owned(),
            },
            Route::Timeline,
            Route::Directory,
            Route::Setup,
            Route::SetupSection {
                // Canonical Realm bootstrap slug (post Realm/Space
                // inversion). `spaces` is still accepted as a legacy
                // alias by SetupPanel::SetupSection::from_slug.
                section: "realms".to_owned(),
            },
            Route::Settings,
            Route::VerifyDevice,
            Route::SpaceAdminSection {
                space_id: "cx:space:roundtrip".to_owned(),
                section: "members".to_owned(),
            },
            // NOTE: Route::Audit / Route::Call / Route::Applets are
            // intentionally omitted — their `View` enum variants were
            // removed (zombie-variant cleanup A6.7), so they map to
            // `View::Dashboard` and would not roundtrip. The routes still
            // exist and still render their panels via the `Route::*` match
            // in `app.rs`; just the View-enum roundtrip no longer applies.
            Route::Kanban,
            Route::Notifications,
            Route::Document,
            Route::DocumentNew,
            Route::Recovery,
            Route::Onboarding,
            Route::Quarantine,
            // G3.Y1 — device / recovery / security panels each get
            // their own dedicated View variant; verify the round-trip.
            Route::SettingsDevices,
            Route::SettingsDevicesPair,
            Route::SettingsRecovery,
            Route::SettingsSecurity,
            Route::Recover,
        ];

        for route in routes {
            let view = route.to_view();
            let back: Route = view.into();
            // The round-trip should produce the same variant (without params)
            assert_eq!(route.to_view(), back.to_view());
        }
    }

    #[test]
    fn test_space_id_extraction() {
        assert_eq!(
            Route::Space {
                space_id: "cx:space:home".to_owned()
            }
            .space_id(),
            Some("cx:space:home")
        );
        assert_eq!(
            Route::TimelineSpace {
                space_id: "cx:space:abc".to_owned()
            }
            .space_id(),
            Some("cx:space:abc")
        );
        assert_eq!(Route::Timeline.space_id(), None);
        assert_eq!(
            Route::SpaceAdminSection {
                space_id: "cx:space:admin".to_owned(),
                section: "members".to_owned(),
            }
            .space_id(),
            Some("cx:space:admin")
        );
    }

    #[test]
    fn test_setup_section_extraction() {
        assert_eq!(
            Route::SetupSection {
                section: "spaces".to_owned()
            }
            .setup_section(),
            Some("spaces")
        );
        assert_eq!(Route::Setup.setup_section(), None);
    }

    #[test]
    fn test_settings_section_extraction() {
        assert_eq!(
            Route::SettingsSection {
                section: "encryption".to_owned()
            }
            .settings_section(),
            Some("encryption")
        );
        assert_eq!(Route::Settings.settings_section(), None);
    }

    #[test]
    fn test_space_admin_section_extraction() {
        assert_eq!(
            Route::SpaceAdminSection {
                space_id: "cx:space:ops".to_owned(),
                section: "repair".to_owned(),
            }
            .space_admin_section(),
            Some("repair")
        );
        assert_eq!(
            Route::SpaceAdmin {
                space_id: "cx:space:ops".to_owned()
            }
            .space_admin_section(),
            None
        );
    }
}
