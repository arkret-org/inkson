//! State retained for the lifetime of the authenticated shell.
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use glory::prelude::*;

pub(super) struct ShellState {
    pub collapsed: Cage<bool>,
    pub width: Cage<f64>,
    pub resizing: Cage<bool>,
    pub mobile_open: Cage<bool>,
    pub mobile_query: Cage<String>,
    pub notifications_open: Cage<bool>,
    pub shortcut_open: Cage<bool>,
    pub account_open: Cage<bool>,
    pub server_open: Cage<bool>,
    pub search_open: Cage<bool>,
    pub search_query: Cage<String>,
    pub tab: Cage<String>,
    pub realm_query: Cage<String>,
    pub contact_query: Cage<String>,
    pub contacts_loaded: Cage<bool>,
    pub agents: Cage<Vec<arkret_sdk::AgentProjection>>,
    pub agents_loaded: Cage<bool>,
    pub own_agents_expanded: Cage<bool>,
    pub expanded_contacts: Cage<BTreeSet<String>>,
    pub row_menu: Cage<Option<String>>,
    pub row_perms: Cage<BTreeMap<String, super::sidebar::SidebarRowRealmPerms>>,
    pub opening: Cage<Option<String>>,
    pub display_name: Cage<String>,
    pub avatar: Cage<String>,
    pub device_name: Cage<String>,
    pub session_status: Cage<String>,
    pub identity_key: Cage<String>,
    pub handles_key: Cage<String>,
    pub pending_leave: Cage<Option<(String, String)>>,
    pub pending_delete: Cage<Option<(String, String)>>,
}
impl ShellState {
    pub fn new(scope: &Scope, context: &crate::presentation::InksonContext) -> Rc<Self> {
        Rc::new(Self {
            collapsed: scope.cage(context.state_store.read(|store| {
                store.load_plain_local_data("sidebar_collapsed").as_deref() == Some("true")
            })),
            width: scope.cage(
                context
                    .state_store
                    .read(super::sidebar_width::load_sidebar_width_preference),
            ),
            resizing: scope.cage(false),
            mobile_open: scope.cage(false),
            mobile_query: scope.cage(String::new()),
            notifications_open: scope.cage(false),
            shortcut_open: scope.cage(false),
            account_open: scope.cage(false),
            server_open: scope.cage(false),
            search_open: scope.cage(false),
            search_query: scope.cage(String::new()),
            tab: scope.cage("collaboration".into()),
            realm_query: scope.cage(String::new()),
            contact_query: scope.cage(String::new()),
            contacts_loaded: scope.cage(false),
            agents: scope.cage(Vec::new()),
            agents_loaded: scope.cage(false),
            own_agents_expanded: scope.cage(true),
            expanded_contacts: scope.cage(BTreeSet::new()),
            row_menu: scope.cage(None),
            row_perms: scope.cage(BTreeMap::new()),
            opening: scope.cage(None),
            display_name: scope.cage(String::new()),
            avatar: scope.cage(String::new()),
            device_name: scope.cage(String::new()),
            session_status: scope.cage(String::new()),
            identity_key: scope.cage(String::new()),
            handles_key: scope.cage(String::new()),
            pending_leave: scope.cage(None),
            pending_delete: scope.cage(None),
        })
    }
}
