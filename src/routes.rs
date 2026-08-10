use dioxus::prelude::*;
use dioxus_router::Routable;

use crate::views::AppView;

/// All navigable routes in the application.
/// Each variant maps to a URL path and a corresponding View.
#[derive(Clone, Debug, PartialEq, Routable)]
pub enum Route {
    #[layout(crate::app::RouterView)]
    #[route("/", RoutePage)]
    Dashboard,

    #[route("/login", RoutePage)]
    Login,

    #[route("/register", RoutePage)]
    Register,

    #[route("/auth/callback", RoutePage)]
    AuthCallback,

    #[route("/realms/manage", RoutePage)]
    RealmsManage,

    #[route("/realms/:realm_id", RealmPage)]
    Realm { realm_id: String },

    /// Optional `?message=` deep-links a single message: the ChatPanel
    /// scrolls it into view and flashes it on arrival. Empty (the common
    /// case) keeps the plain per-realm behavior. See design/route-view-ia.md
    /// §3.2.
    #[route("/chat/:realm_id?:message", ChatRealmPage)]
    Chat { realm_id: String, message: String },

    #[route("/direct/:realm_id/:strand_id", DirectConversationPage)]
    DirectConversation { realm_id: String, strand_id: String },

    #[route("/directory", RoutePage)]
    Directory,

    #[route("/contacts/manage", RoutePage)]
    ContactsManage,

    #[route("/contacts", RoutePage)]
    Contacts,

    #[route("/files", RoutePage)]
    FileTransfer,

    #[route("/setup", RoutePage)]
    Setup,

    #[route("/setup/:section", SetupSectionPage)]
    SetupSection { section: String },

    #[route("/settings", RoutePage)]
    Settings,

    /// G3.Y1 — device management (list + revoke). Static segment so
    /// dioxus-router matches this before `/settings/:section` falls
    /// through to the generic `SettingsPanel`.
    #[route("/settings/devices", RoutePage)]
    SettingsDevices,

    /// G3.Y1 — QR-driven pairing for a sibling device. Live on its
    /// own URL so the e2e harness can deep-link into the pair strand
    /// without scrolling through the device list.
    #[route("/settings/devices/pair", RoutePage)]
    SettingsDevicesPair,

    /// Recovery settings. Hosts the broader recovery-options aggregator
    /// under the Settings shell.
    #[route("/settings/recovery", RoutePage)]
    SettingsRecovery,

    #[route("/settings/:section?:filter", SettingsSectionPage)]
    SettingsSection { section: String, filter: String },

    #[route("/devices/verify", RoutePage)]
    VerifyDevice,

    #[route("/realms/:realm_id/members", RealmMembersPage)]
    RealmMembers { realm_id: String },

    #[route("/realms/:realm_id/circles", CirclesPage)]
    Circles { realm_id: String },

    #[route("/realms/:realm_id/circles/:circle_id", CircleDetailPage)]
    CircleDetail { realm_id: String, circle_id: String },

    #[route("/realms/:realm_id/settings", RealmAdminPage)]
    RealmAdmin { realm_id: String },

    #[route("/realms/:realm_id/settings/:section", RealmAdminSectionPage)]
    RealmAdminSection { realm_id: String, section: String },

    #[route("/audit", RoutePage)]
    Audit,

    /// T7.1 — Developer Tools / Diagnostics aggregator. Hosts the
    /// protocol-level details (schema ids, event kinds, raw event log,
    /// profile id, conformance) that used to leak into the main strand.
    #[route("/developer", RoutePage)]
    Developer,

    #[route("/kanban", RoutePage)]
    Kanban,

    #[route("/kanban/:realm_id", KanbanRealmPage)]
    KanbanRealm { realm_id: String },

    /// AKP board-persistence — the selected Board id is part of the URL
    /// so a page refresh (or a deep link) restores the exact board the
    /// user was looking at instead of falling back to
    /// `board_options.first()`. `realm_id` is the Realm id; `board_id`
    /// is the board Space-container id.
    #[route("/kanban/:realm_id/board/:board_id", KanbanBoardPage)]
    KanbanBoard { realm_id: String, board_id: String },

    /// Board + card-detail deep link. Carries the board id alongside the
    /// strand id so a refresh on an open card restores the right board
    /// even when the card is a locally-queued draft the server
    /// projection does not yet know about.
    #[route("/kanban/:realm_id/board/:board_id/task/:task_id", KanbanBoardTaskPage)]
    KanbanBoardTask {
        realm_id: String,
        board_id: String,
        task_id: String,
    },

    /// Board-less card deep link. Retained for share links / global
    /// search results that only know the strand id; the board is resolved
    /// from the projection (or local queue) on arrival.
    #[route("/kanban/:realm_id/task/:task_id", KanbanTaskPage)]
    KanbanTask { realm_id: String, task_id: String },

    #[route("/notifications", RoutePage)]
    Notifications,

    #[route("/notifications/settings", NotificationsSettingsPage)]
    NotificationsSettings,

    /// Live call surface. Optional query params deep-link an in-progress
    /// or outgoing call: `call_id` (the `ak:call:…` id), `peer` (the 1:1
    /// callee DID, empty for SFU group calls), `realm_id`, `video` (`1`
    /// for a video call, else audio-only), and `incoming` (`1` when this
    /// is an inbound ring being answered).
    #[route("/call?:call_id&:peer&:realm_id&:video&:incoming", CallPage)]
    Call {
        call_id: String,
        peer: String,
        realm_id: String,
        video: String,
        incoming: String,
    },

    #[route("/recovery", RoutePage)]
    Recovery,

    #[route("/onboarding", RoutePage)]
    Onboarding,

    #[route("/quarantine", RoutePage)]
    Quarantine,

    #[route("/applets", RoutePage)]
    Applets,

    /// A6.1 — global cross-Space message search. Triggered by Cmd+F
    /// (Ctrl+F on non-Mac), the topbar `topbar-search-button`, or by
    /// directly navigating to `/search`. The current Arkret catalog has no
    /// spec-defined HTTP endpoint for global index search, so the panel fails
    /// closed until a catalog entry lands.
    #[route("/search", RoutePage)]
    Search,
}

#[component]
fn RoutePage() -> Element {
    rsx! {}
}

#[component]
fn ChatRealmPage(realm_id: String, message: String) -> Element {
    let _ = (realm_id, message);
    rsx! {}
}

#[component]
fn DirectConversationPage(realm_id: String, strand_id: String) -> Element {
    let _ = (realm_id, strand_id);
    rsx! {}
}

#[component]
fn RealmPage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! {}
}

#[component]
fn RealmMembersPage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! {}
}

#[component]
fn CirclesPage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! {}
}

#[component]
fn CircleDetailPage(realm_id: String, circle_id: String) -> Element {
    let _ = (realm_id, circle_id);
    rsx! {}
}

#[component]
fn SettingsSectionPage(section: String, filter: String) -> Element {
    let _ = (section, filter);
    rsx! {}
}

#[component]
fn SetupSectionPage(section: String) -> Element {
    let _ = section;
    rsx! {}
}

#[component]
fn RealmAdminPage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! {}
}

#[component]
fn RealmAdminSectionPage(realm_id: String, section: String) -> Element {
    let _ = (realm_id, section);
    rsx! {}
}

#[component]
fn KanbanRealmPage(realm_id: String) -> Element {
    let _ = realm_id;
    rsx! {}
}

#[component]
fn KanbanTaskPage(realm_id: String, task_id: String) -> Element {
    let _ = (realm_id, task_id);
    rsx! {}
}

#[component]
fn KanbanBoardPage(realm_id: String, board_id: String) -> Element {
    let _ = (realm_id, board_id);
    rsx! {}
}

#[component]
fn KanbanBoardTaskPage(realm_id: String, board_id: String, task_id: String) -> Element {
    let _ = (realm_id, board_id, task_id);
    rsx! {}
}

#[component]
fn NotificationsSettingsPage() -> Element {
    rsx! {}
}

#[component]
fn CallPage(
    call_id: String,
    peer: String,
    realm_id: String,
    video: String,
    incoming: String,
) -> Element {
    let _ = (call_id, peer, realm_id, video, incoming);
    rsx! {}
}

impl Route {
    /// Convert a Route to the corresponding View enum variant.
    pub fn to_view(&self) -> AppView {
        match self {
            Route::Dashboard => AppView::Dashboard,
            Route::Login | Route::Register | Route::AuthCallback => AppView::Login,
            Route::RealmsManage => AppView::RealmsManage,
            // `/realms/:id` is an entry point, not a surface: it resolves the
            // user's RealmSurface preference and renders the board
            // (design/route-view-ia.md §3.1, plan A). It shares the Kanban view.
            Route::Realm { .. } => AppView::Kanban,
            Route::Chat { .. } | Route::DirectConversation { .. } => AppView::Chat,
            Route::Contacts | Route::ContactsManage => AppView::Contacts,
            Route::FileTransfer => AppView::FileTransfer,
            Route::Directory => AppView::Directory,
            Route::Setup | Route::SetupSection { .. } => AppView::Setup,
            Route::Settings
            | Route::SettingsSection { .. }
            | Route::NotificationsSettings
            | Route::SettingsDevices
            | Route::SettingsDevicesPair
            | Route::SettingsRecovery
            | Route::Recovery
            | Route::Audit
            | Route::Developer => AppView::Settings,
            Route::VerifyDevice => AppView::VerifyDevice,
            Route::Circles { .. } | Route::CircleDetail { .. } => AppView::Circles,
            Route::RealmMembers { .. }
            | Route::RealmAdmin { .. }
            | Route::RealmAdminSection { .. } => AppView::RealmAdmin,
            Route::Call { .. } => AppView::Call,
            Route::Applets => AppView::Applets,
            Route::Kanban
            | Route::KanbanRealm { .. }
            | Route::KanbanBoard { .. }
            | Route::KanbanBoardTask { .. }
            | Route::KanbanTask { .. } => AppView::Kanban,
            Route::Notifications => AppView::Notifications,
            Route::Onboarding => AppView::Onboarding,
            Route::Quarantine => AppView::Quarantine,
            Route::Search => AppView::Search,
        }
    }

    /// Extract realm_id from routes that carry a Realm context.
    pub fn realm_id(&self) -> Option<&str> {
        match self {
            Route::Realm { realm_id }
            | Route::Chat { realm_id, .. }
            | Route::DirectConversation { realm_id, .. }
            | Route::KanbanRealm { realm_id }
            | Route::KanbanBoard { realm_id, .. }
            | Route::KanbanBoardTask { realm_id, .. }
            | Route::KanbanTask { realm_id, .. }
            | Route::RealmMembers { realm_id }
            | Route::Circles { realm_id }
            | Route::CircleDetail { realm_id, .. }
            | Route::RealmAdmin { realm_id }
            | Route::RealmAdminSection { realm_id, .. } => Some(realm_id.as_str()),
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
            Route::SettingsSection { section, .. } => Some(section.as_str()),
            Route::NotificationsSettings => Some("notifications"),
            Route::SettingsDevices | Route::SettingsDevicesPair => Some("devices"),
            Route::SettingsRecovery | Route::Recovery => Some("recovery"),
            Route::Audit => Some("audit"),
            Route::Developer => Some("developer"),
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
impl From<AppView> for Route {
    fn from(view: AppView) -> Self {
        match view {
            AppView::Dashboard => Route::Dashboard,
            AppView::Login => Route::Login,
            AppView::Chat => Route::Chat {
                realm_id: String::new(),
                message: String::new(),
            },
            AppView::Contacts => Route::Contacts,
            AppView::FileTransfer => Route::FileTransfer,
            AppView::Directory => Route::Directory,
            AppView::Setup => Route::Setup,
            AppView::Settings => Route::Settings,
            AppView::SettingsDevices => Route::SettingsDevices,
            AppView::SettingsRecovery => Route::SettingsRecovery,
            AppView::VerifyDevice => Route::VerifyDevice,
            AppView::RealmAdmin => Route::RealmAdmin {
                realm_id: String::new(),
            },
            AppView::Circles => Route::Circles {
                realm_id: String::new(),
            },
            AppView::Kanban => Route::Kanban,
            AppView::RealmsManage => Route::RealmsManage,
            AppView::Call => Route::Call {
                call_id: String::new(),
                peer: String::new(),
                realm_id: String::new(),
                video: String::new(),
                incoming: String::new(),
            },
            AppView::Applets => Route::Applets,
            AppView::Notifications => Route::Notifications,
            AppView::Recovery => Route::Recovery,
            AppView::Onboarding => Route::Onboarding,
            AppView::Quarantine => Route::Quarantine,
            AppView::Search => Route::Search,
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
            Route::Register,
            Route::Realm {
                realm_id: "ak:realm:Ah-TN8ceKyXkuwRp9fuEVw7pwATVHa-ISAbDJQgUm9hA".to_owned(),
            },
            Route::Directory,
            Route::FileTransfer,
            Route::Setup,
            Route::SetupSection {
                // Canonical Realm bootstrap slug.
                section: "realms".to_owned(),
            },
            Route::Settings,
            Route::VerifyDevice,
            Route::RealmAdminSection {
                realm_id: "ak:realm:Ah-TN8ceKyXkuwRp9fuEVw7pwATVHa-ISAbDJQgUm9hA".to_owned(),
                section: "access".to_owned(),
            },
            Route::RealmMembers {
                realm_id: "ak:realm:Ah-TN8ceKyXkuwRp9fuEVw7pwATVHa-ISAbDJQgUm9hA".to_owned(),
            },
            Route::Audit,
            Route::Developer,
            Route::RealmsManage,
            Route::Call {
                call_id: String::new(),
                peer: String::new(),
                realm_id: String::new(),
                video: String::new(),
                incoming: String::new(),
            },
            Route::Applets,
            Route::Kanban,
            Route::Notifications,
            Route::Recovery,
            Route::Onboarding,
            Route::Quarantine,
            // G3.Y1 settings subroutes all round-trip through AppView::Settings.
            Route::SettingsDevices,
            Route::SettingsDevicesPair,
            Route::SettingsRecovery,
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
                realm_id: "ak:realm:A28oJpDpEI80mVokdt5Yo0vuv0Z1SXEPt1X593Rirmn8".to_owned()
            }
            .realm_id(),
            Some("ak:realm:A28oJpDpEI80mVokdt5Yo0vuv0Z1SXEPt1X593Rirmn8")
        );
        assert_eq!(
            Route::RealmAdminSection {
                realm_id: "ak:realm:AgQ3wZKVHQtgzsB-kFz2dtmKzjMrfywHYcRpK4h4_jbo".to_owned(),
                section: "access".to_owned(),
            }
            .realm_id(),
            Some("ak:realm:AgQ3wZKVHQtgzsB-kFz2dtmKzjMrfywHYcRpK4h4_jbo")
        );
        assert_eq!(
            Route::RealmMembers {
                realm_id: "ak:realm:AwwMJvEXGOqIP4f1n5k7Youiz7BKg0kUqt_LIVo22FFk".to_owned()
            }
            .realm_id(),
            Some("ak:realm:AwwMJvEXGOqIP4f1n5k7Youiz7BKg0kUqt_LIVo22FFk")
        );
    }

    #[test]
    fn test_setup_section_extraction() {
        assert_eq!(
            Route::SetupSection {
                section: "realms".to_owned()
            }
            .setup_section(),
            Some("realms")
        );
        assert_eq!(Route::Setup.setup_section(), None);
    }

    #[test]
    fn test_settings_section_extraction() {
        assert_eq!(
            Route::SettingsSection {
                section: "encryption".to_owned(),
                filter: String::new(),
            }
            .settings_section(),
            Some("encryption")
        );
        assert_eq!(Route::SettingsDevices.settings_section(), Some("devices"));
        assert_eq!(Route::SettingsRecovery.settings_section(), Some("recovery"));
        assert_eq!(Route::Audit.settings_section(), Some("audit"));
        assert_eq!(Route::Developer.settings_section(), Some("developer"));
        assert_eq!(Route::Settings.settings_section(), None);
    }

    #[test]
    fn test_realm_admin_section_extraction() {
        assert_eq!(
            Route::RealmAdminSection {
                realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
                section: "repair".to_owned(),
            }
            .realm_admin_section(),
            Some("repair")
        );
        assert_eq!(
            Route::RealmAdmin {
                realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned()
            }
            .realm_admin_section(),
            None
        );
    }
}
