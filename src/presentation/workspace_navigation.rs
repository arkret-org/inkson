//! Retained list/detail presentation, independent from account data and routes.
use glory::prelude::*;

use crate::routes::Route;

#[derive(Clone)]
pub struct WorkspaceNavigation {
    pub layout: sapid::ShellLayout,
    pub list_expanded: Cage<bool>,
    pub detail_open: Cage<bool>,
    pub settings_query: Cage<String>,
}

impl WorkspaceNavigation {
    pub fn new(scope: &Scope, route: &Route) -> Self {
        #[cfg_attr(
            not(test),
            expect(
                clippy::expect_used,
                reason = "The fixed finite width and positive breakpoint satisfy ShellLayout validation"
            )
        )]
        let layout =
            sapid::ShellLayout::new(scope, 1024.0, 861.0).expect("valid workspace breakpoint");
        Self {
            layout,
            list_expanded: scope.cage(true),
            detail_open: scope.cage(route_opens_detail(route)),
            settings_query: scope.cage(String::new()),
        }
    }

    pub fn navigate(&self, route: &Route) {
        self.detail_open
            .revise(|value| *value = route_opens_detail(route));
    }

    pub fn open_detail(&self) {
        self.detail_open.revise(|value| *value = true);
    }

    pub fn show_list(&self) {
        self.detail_open.revise(|value| *value = false);
    }

    pub fn pane_visible(&self, detail: bool) -> bool {
        if self.layout.mobile().get() {
            self.detail_open.get() == detail
        } else {
            detail || self.list_expanded.get()
        }
    }
}

fn route_opens_detail(route: &Route) -> bool {
    !matches!(
        route,
        Route::Contacts | Route::RealmsManage | Route::Settings
    ) && !matches!(route, Route::SettingsSection { section, .. } if section == "agents")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mobile_selection_back_and_desktop_collapse_are_independent() {
        let app = App::new(glory::render::memory::Memory::new);
        let navigation = WorkspaceNavigation::new(app.scope(), &Route::Contacts);
        navigation.layout.observe_width(390.0).unwrap();
        assert!(navigation.pane_visible(false));
        assert!(!navigation.pane_visible(true));
        navigation.open_detail();
        assert!(!navigation.pane_visible(false));
        assert!(navigation.pane_visible(true));
        navigation.show_list();
        navigation.layout.observe_width(1280.0).unwrap();
        assert!(navigation.pane_visible(false));
        assert!(navigation.pane_visible(true));
        navigation.list_expanded.revise(|value| *value = false);
        assert!(!navigation.pane_visible(false));
        assert!(navigation.pane_visible(true));
        navigation.layout.observe_width(390.0).unwrap();
        assert!(navigation.pane_visible(false));
        assert!(!navigation.pane_visible(true));
    }

    #[test]
    fn entry_routes_show_the_list_and_deep_links_show_detail() {
        for route in [
            Route::Contacts,
            Route::RealmsManage,
            Route::Settings,
            Route::SettingsSection {
                section: "agents".into(),
                filter: "active".into(),
            },
        ] {
            assert!(!route_opens_detail(&route));
        }
        for route in [
            Route::SettingsDevices,
            Route::SettingsSection {
                section: "theme".into(),
                filter: String::new(),
            },
            Route::Realm {
                realm_id: "accepted".into(),
            },
            Route::SetupSection {
                section: "realms".into(),
            },
        ] {
            assert!(route_opens_detail(&route));
        }
    }
}
