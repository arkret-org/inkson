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

    #[route("/directory", crate::app::RouterView)]
    Directory,

    #[route("/setup", crate::app::RouterView)]
    Setup,

    #[route("/setup/:section", SetupSectionPage)]
    SetupSection { section: String },

    #[route("/settings", crate::app::RouterView)]
    Settings,

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

    #[route("/kanban", crate::app::RouterView)]
    Kanban,

    #[route("/kanban/:space_id", KanbanSpacePage)]
    KanbanSpace { space_id: String },

    #[route("/chat", crate::app::RouterView)]
    Chat,

    #[route("/chat/:space_id", ChatSpacePage)]
    ChatSpace { space_id: String },

    #[route("/notifications", crate::app::RouterView)]
    Notifications,

    #[route("/document", crate::app::RouterView)]
    Document,

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

    /// Agent Workspace — controller's private mirror Space entry.
    /// Spec `cx.profile.agent_workspace.v1`.
    #[route("/agent-workspace", crate::app::RouterView)]
    AgentWorkspace,

    /// Single agent_task detail page.
    #[route("/agent-workspace/task/:task_id", AgentTaskPage)]
    AgentTask { task_id: String },
}

#[component]
fn AgentTaskPage(task_id: String) -> Element {
    let _ = task_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn TimelineSpacePage(space_id: String) -> Element {
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
fn ChatSpacePage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn DocumentSpacePage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

impl Route {
    /// Convert a Route to the corresponding View enum variant.
    pub fn to_view(&self) -> View {
        match self {
            Route::Dashboard => View::Dashboard,
            Route::Login | Route::AuthCallback => View::Login,
            Route::Space { .. } => View::Timeline,
            Route::Timeline | Route::TimelineSpace { .. } => View::Timeline,
            Route::Directory => View::Directory,
            Route::Setup | Route::SetupSection { .. } => View::Setup,
            Route::Settings | Route::SettingsSection { .. } => View::Settings,
            Route::VerifyDevice => View::VerifyDevice,
            Route::SpaceAdmin { .. } | Route::SpaceAdminSection { .. } => View::SpaceAdmin,
            Route::Audit => View::Audit,
            Route::Kanban | Route::KanbanSpace { .. } => View::Kanban,
            Route::Chat | Route::ChatSpace { .. } => View::Chat,
            Route::Notifications => View::Notifications,
            Route::Document | Route::DocumentSpace { .. } => View::Document,
            Route::Call => View::Call,
            Route::Recovery => View::Recovery,
            Route::Onboarding => View::Onboarding,
            Route::Quarantine => View::Quarantine,
            Route::Applets => View::Applets,
            Route::Agents => View::Agents,
            Route::AgentWorkspace | Route::AgentTask { .. } => View::AgentWorkspace,
        }
    }

    /// Extract space_id from routes that carry one.
    pub fn space_id(&self) -> Option<&str> {
        match self {
            Route::Space { space_id }
            | Route::TimelineSpace { space_id }
            | Route::KanbanSpace { space_id }
            | Route::ChatSpace { space_id }
            | Route::DocumentSpace { space_id }
            | Route::SpaceAdmin { space_id }
            | Route::SpaceAdminSection { space_id, .. } => Some(space_id.as_str()),
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
            View::Directory => Route::Directory,
            View::Setup => Route::Setup,
            View::Settings => Route::Settings,
            View::VerifyDevice => Route::VerifyDevice,
            View::SpaceAdmin => Route::SpaceAdmin {
                space_id: String::new(),
            },
            View::Audit => Route::Audit,
            View::Kanban => Route::Kanban,
            View::Chat => Route::Chat,
            View::Notifications => Route::Notifications,
            View::Document => Route::Document,
            View::Call => Route::Call,
            View::Recovery => Route::Recovery,
            View::Onboarding => Route::Onboarding,
            View::Quarantine => Route::Quarantine,
            View::Applets => Route::Applets,
            View::Agents => Route::Agents,
            View::AgentWorkspace => Route::AgentWorkspace,
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
                section: "spaces".to_owned(),
            },
            Route::Settings,
            Route::VerifyDevice,
            Route::SpaceAdminSection {
                space_id: "cx:space:roundtrip".to_owned(),
                section: "members".to_owned(),
            },
            Route::Audit,
            Route::Kanban,
            Route::Chat,
            Route::Notifications,
            Route::Document,
            Route::Call,
            Route::Recovery,
            Route::Onboarding,
            Route::Quarantine,
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
            Route::ChatSpace {
                space_id: "cx:space:xyz".to_owned()
            }
            .space_id(),
            Some("cx:space:xyz")
        );
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
