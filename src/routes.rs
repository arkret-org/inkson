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

    #[route("/realms/:realm_id", RealmPage)]
    Realm { realm_id: String },

    #[route("/timeline/:realm_id", TimelineSpacePage)]
    TimelineSpace { realm_id: String },

    #[route("/timeline/:realm_id/message/:message_id", TimelineMessagePage)]
    TimelineMessage {
        realm_id: String,
        message_id: String,
    },

    #[route("/chat/:realm_id", ChatSpacePage)]
    Chat { realm_id: String },

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
    /// buttons. Backed by soland's `ck.schema.key_backup.v1` endpoints
    /// (`PUT/GET /_cokret/self/keys/backups/{backup_id}`) plus the local MLS
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

    #[route("/realms/:realm_id/admin", RealmAdminPage)]
    RealmAdmin { realm_id: String },

    #[route("/realms/:realm_id/admin/:section", RealmAdminSectionPage)]
    RealmAdminSection {
        realm_id: String,
        section: String,
    },

    #[route("/audit", crate::app::RouterView)]
    Audit,

    /// T7.1 — Developer Tools / Diagnostics aggregator. Hosts the
    /// protocol-level details (schema ids, event kinds, raw event log,
    /// profile id, conformance) that used to leak into the main flow.
    #[route("/developer", crate::app::RouterView)]
    Developer,

    #[route("/kanban", crate::app::RouterView)]
    Kanban,

    #[route("/kanban/:realm_id", KanbanSpacePage)]
    KanbanSpace { realm_id: String },

    /// CKP board-persistence — the selected Board id is part of the URL
    /// so a page refresh (or a deep link) restores the exact board the
    /// user was looking at instead of falling back to
    /// `board_options.first()`. `realm_id` is the Realm id; `board_id`
    /// is the board Space-container id.
    #[route("/kanban/:realm_id/board/:board_id", KanbanBoardPage)]
    KanbanBoard {
        realm_id: String,
        board_id: String,
    },

    /// Board + card-detail deep link. Carries the board id alongside the
    /// flow id so a refresh on an open card restores the right board
    /// even when the card is a locally-queued draft the server
    /// projection does not yet know about.
    #[route("/kanban/:realm_id/board/:board_id/task/:task_id", KanbanBoardTaskPage)]
    KanbanBoardTask {
        realm_id: String,
        board_id: String,
        task_id: String,
    },

    /// Board-less card deep link. Retained for share links / global
    /// search results that only know the flow id; the board is resolved
    /// from the projection (or local queue) on arrival.
    #[route("/kanban/:realm_id/task/:task_id", KanbanTaskPage)]
    KanbanTask {
        realm_id: String,
        task_id: String,
    },

    #[route("/notifications", crate::app::RouterView)]
    Notifications,

    #[route("/notifications/settings", NotificationsSettingsPage)]
    NotificationsSettings,

    #[route("/document", crate::app::RouterView)]
    Document,

    #[route("/document/new", crate::app::RouterView)]
    DocumentNew,

    #[route("/document/:realm_id", DocumentSpacePage)]
    DocumentSpace { realm_id: String },

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
    /// `POST /_soland/self/index/search` substring scan.
    #[route("/search", crate::app::RouterView)]
    Search,
}

#[component]
fn TimelineSpacePage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn TimelineMessagePage(realm_id: String, message_id: String) -> Element {
    let _ = (realm_id, message_id);
    rsx! { crate::app::RouterView {} }
}

#[component]
fn ChatSpacePage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn RealmPage(realm_id: String) -> Element {
    let _ = realm_id;
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
fn RealmAdminPage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn RealmAdminSectionPage(realm_id: String, section: String) -> Element {
    let _ = (realm_id, section);
    rsx! { crate::app::RouterView {} }
}

#[component]
fn KanbanSpacePage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn KanbanTaskPage(realm_id: String, task_id: String) -> Element {
    let _ = (realm_id, task_id);
    rsx! { crate::app::RouterView {} }
}

#[component]
fn KanbanBoardPage(realm_id: String, board_id: String) -> Element {
    let _ = (realm_id, board_id);
    rsx! { crate::app::RouterView {} }
}

#[component]
fn KanbanBoardTaskPage(realm_id: String, board_id: String, task_id: String) -> Element {
    let _ = (realm_id, board_id, task_id);
    rsx! { crate::app::RouterView {} }
}

#[component]
fn DocumentSpacePage(realm_id: String) -> Element {
    let _ = realm_id;
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
            Route::Realm { .. } => View::Timeline,
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
            Route::RealmAdmin { .. } | Route::RealmAdminSection { .. } => View::RealmAdmin,
            // Audit / Call / Applets routes still render their own panels
            // (see `Route::Audit`/`Route::Call`/`Route::Applets` arms in
            // `app.rs`) but no longer have dedicated `View` enum variants —
            // the variants were unreferenced anywhere except this mapping,
            // and nothing in the UI dispatches on them. Map to Dashboard so
            // `view` signal stays consistent for sidebar / palette state.
            Route::Audit | Route::Call | Route::Applets | Route::Developer => View::Dashboard,
            Route::Kanban
            | Route::KanbanSpace { .. }
            | Route::KanbanBoard { .. }
            | Route::KanbanBoardTask { .. }
            | Route::KanbanTask { .. } => View::Kanban,
            Route::Notifications => View::Notifications,
            Route::Document | Route::DocumentNew | Route::DocumentSpace { .. } => View::Document,
            Route::Recovery => View::Recovery,
            Route::Onboarding => View::Onboarding,
            Route::Quarantine => View::Quarantine,
            Route::Agents => View::Agents,
            Route::Search => View::Search,
        }
    }

    /// Extract realm_id from routes that carry a Realm context.
    pub fn realm_id(&self) -> Option<&str> {
        match self {
            Route::Realm { realm_id }
            | Route::TimelineSpace { realm_id }
            | Route::TimelineMessage { realm_id, .. }
            | Route::Chat { realm_id }
            | Route::KanbanSpace { realm_id }
            | Route::KanbanBoard { realm_id, .. }
            | Route::KanbanBoardTask { realm_id, .. }
            | Route::KanbanTask { realm_id, .. }
            | Route::RealmAdmin { realm_id }
            | Route::RealmAdminSection { realm_id, .. } => Some(realm_id.as_str()),
            Route::DocumentSpace { realm_id } if !realm_id.starts_with("ck:morph:") => {
                Some(realm_id.as_str())
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

    /// Extract Realm admin section from routes that carry one.
    pub fn realm_admin_section(&self) -> Option<&str> {
        match self {
            Route::RealmAdminSection { section, .. } => Some(section.as_str()),
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
                realm_id: String::new(),
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
            View::RealmAdmin => Route::RealmAdmin {
                realm_id: String::new(),
            },
            View::Kanban => Route::Kanban,
            View::Notifications => Route::Notifications,
            View::Document => Route::DocumentNew,
            View::Recovery => Route::Recovery,
            View::Onboarding => Route::Onboarding,
            View::Quarantine => Route::Quarantine,
            View::Agents => Route::Agents,
            View::Search => Route::Search,
            // CKP-0007 P3B.2.5: Circle detail view. Default URL points
            // at the dashboard because the canonical `/circles/:id`
            // route carries a Circle id that is not addressable from
            // the View enum alone. The deep-link entry point is the
            // sidebar / picker row click, not the sidebar nav rail.
            View::Circle => Route::Dashboard,
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
            Route::Realm {
                realm_id: "ck:realm:roundtrip".to_owned(),
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
            Route::RealmAdminSection {
                realm_id: "ck:realm:roundtrip".to_owned(),
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
    fn test_realm_id_extraction() {
        assert_eq!(
            Route::Realm {
                realm_id: "ck:realm:home".to_owned()
            }
            .realm_id(),
            Some("ck:realm:home")
        );
        assert_eq!(
            Route::TimelineSpace {
                realm_id: "ck:realm:abc".to_owned()
            }
            .realm_id(),
            Some("ck:realm:abc")
        );
        assert_eq!(Route::Timeline.realm_id(), None);
        assert_eq!(
            Route::RealmAdminSection {
                realm_id: "ck:realm:admin".to_owned(),
                section: "members".to_owned(),
            }
            .realm_id(),
            Some("ck:realm:admin")
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
    fn test_realm_admin_section_extraction() {
        assert_eq!(
            Route::RealmAdminSection {
                realm_id: "ck:realm:ops".to_owned(),
                section: "repair".to_owned(),
            }
            .realm_admin_section(),
            Some("repair")
        );
        assert_eq!(
            Route::RealmAdmin {
                realm_id: "ck:realm:ops".to_owned()
            }
            .realm_admin_section(),
            None
        );
    }
}
