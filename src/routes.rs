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

    #[route("/register", crate::app::RouterView)]
    Register,

    #[route("/timeline", crate::app::RouterView)]
    Timeline,

    #[route("/timeline/:space_id", TimelineSpacePage)]
    TimelineSpace { space_id: String },

    #[route("/directory", crate::app::RouterView)]
    Directory,

    #[route("/product", crate::app::RouterView)]
    Product,

    #[route("/settings", crate::app::RouterView)]
    Settings,

    #[route("/settings/:section", SettingsSectionPage)]
    SettingsSection { section: String },

    #[route("/devices", crate::app::RouterView)]
    Devices,

    #[route("/devices/verify", crate::app::RouterView)]
    VerifyDevice,

    #[route("/readiness", crate::app::RouterView)]
    Readiness,

    #[route("/space/:space_id/admin", SpaceAdminPage)]
    SpaceAdmin { space_id: String },

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

    #[route("/forum", crate::app::RouterView)]
    Forum,

    #[route("/memory", crate::app::RouterView)]
    MemoryReview,

    #[route("/agents", crate::app::RouterView)]
    AgentRuns,

    #[route("/notifications", crate::app::RouterView)]
    Notifications,

    #[route("/document", crate::app::RouterView)]
    Document,

    #[route("/document/:space_id", DocumentSpacePage)]
    DocumentSpace { space_id: String },

    #[route("/call", crate::app::RouterView)]
    Call,
}

#[component]
fn TimelineSpacePage(space_id: String) -> Element {
    let _ = space_id;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn SettingsSectionPage(section: String) -> Element {
    let _ = section;
    rsx! { crate::app::RouterView {} }
}

#[component]
fn SpaceAdminPage(space_id: String) -> Element {
    let _ = space_id;
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
            Route::Login => View::Login,
            Route::Register => View::Register,
            Route::Timeline | Route::TimelineSpace { .. } => View::Timeline,
            Route::Directory => View::Directory,
            Route::Product => View::Product,
            Route::Settings | Route::SettingsSection { .. } => View::Settings,
            Route::Devices => View::Devices,
            Route::VerifyDevice => View::VerifyDevice,
            Route::Readiness => View::Readiness,
            Route::SpaceAdmin { .. } => View::SpaceAdmin,
            Route::Audit => View::Audit,
            Route::Kanban | Route::KanbanSpace { .. } => View::Kanban,
            Route::Chat | Route::ChatSpace { .. } => View::Chat,
            Route::Forum => View::Forum,
            Route::MemoryReview => View::MemoryReview,
            Route::AgentRuns => View::AgentRuns,
            Route::Notifications => View::Notifications,
            Route::Document | Route::DocumentSpace { .. } => View::Document,
            Route::Call => View::Call,
        }
    }

    /// Extract space_id from routes that carry one.
    pub fn space_id(&self) -> Option<&str> {
        match self {
            Route::TimelineSpace { space_id }
            | Route::KanbanSpace { space_id }
            | Route::ChatSpace { space_id }
            | Route::DocumentSpace { space_id }
            | Route::SpaceAdmin { space_id } => Some(space_id.as_str()),
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
}

/// Convert a View enum variant to the default Route for that view.
impl From<View> for Route {
    fn from(view: View) -> Self {
        match view {
            View::Dashboard => Route::Dashboard,
            View::Login => Route::Login,
            View::Register => Route::Register,
            View::Timeline => Route::Timeline,
            View::Directory => Route::Directory,
            View::Product => Route::Product,
            View::Settings => Route::Settings,
            View::Devices => Route::Devices,
            View::VerifyDevice => Route::VerifyDevice,
            View::Readiness => Route::Readiness,
            View::SpaceAdmin => Route::SpaceAdmin {
                space_id: String::new(),
            },
            View::Audit => Route::Audit,
            View::Kanban => Route::Kanban,
            View::Chat => Route::Chat,
            View::Forum => Route::Forum,
            View::MemoryReview => Route::MemoryReview,
            View::AgentRuns => Route::AgentRuns,
            View::Notifications => Route::Notifications,
            View::Document => Route::Document,
            View::Call => Route::Call,
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
            Route::Timeline,
            Route::Directory,
            Route::Product,
            Route::Settings,
            Route::Devices,
            Route::VerifyDevice,
            Route::Readiness,
            Route::Audit,
            Route::Kanban,
            Route::Chat,
            Route::Forum,
            Route::MemoryReview,
            Route::AgentRuns,
            Route::Notifications,
            Route::Document,
            Route::Call,
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
}
