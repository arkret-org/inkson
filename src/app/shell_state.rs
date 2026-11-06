//! State retained for the lifetime of the authenticated shell.
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use glory::prelude::*;

pub(super) struct ShellState {
    pub mobile_open: Cage<bool>,
    pub mobile_query: Cage<String>,
    pub notifications_open: Cage<bool>,
    pub shortcut_open: Cage<bool>,
    pub account_open: Cage<bool>,
    pub search_open: Cage<bool>,
    pub search_query: Cage<String>,
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
    pub pending_leave: Cage<Option<(String, String)>>,
    pub pending_delete: Cage<Option<(String, String)>>,
}
impl ShellState {
    pub fn new(scope: &Scope, _context: &crate::presentation::InksonContext) -> Rc<Self> {
        Rc::new(Self {
            mobile_open: scope.cage(false),
            mobile_query: scope.cage(String::new()),
            notifications_open: scope.cage(false),
            shortcut_open: scope.cage(false),
            account_open: scope.cage(false),
            search_open: scope.cage(false),
            search_query: scope.cage(String::new()),
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
            pending_leave: scope.cage(None),
            pending_delete: scope.cage(None),
        })
    }
}
