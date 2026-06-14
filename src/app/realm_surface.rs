//! Per-realm surface (Timeline/Board/Document) selection: the `RealmSurface`
//! enum + its label/route/availability helpers, the private-data preference
//! load/persist pair, and the route→surface resolution used by the router
//! reconcile. Moved out of `app.rs` (YOU-07-001, move only); re-exported from
//! the parent so inline call sites and `app_tests.rs` `use super::*` resolve
//! unchanged.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RealmSurface {
    Timeline,
    Board,
    Document,
}

impl RealmSurface {
    pub(crate) fn top_nav() -> [Self; 3] {
        [Self::Timeline, Self::Board, Self::Document]
    }

    pub(crate) fn short_label(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline",
            Self::Board => "Board",
            Self::Document => "Document",
        }
    }

    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline View",
            Self::Board => "Board View",
            Self::Document => "Document View",
        }
    }

    pub(crate) fn icon_name(self) -> &'static str {
        match self {
            Self::Timeline => "timeline",
            Self::Board => "board",
            Self::Document => "file",
        }
    }

    pub(crate) fn preference_value(self) -> &'static str {
        match self {
            Self::Timeline => "timeline",
            Self::Board => "board",
            Self::Document => "document",
        }
    }

    pub(crate) fn from_preference(value: &str) -> Option<Self> {
        match value {
            "timeline" => Some(Self::Timeline),
            "board" => Some(Self::Board),
            "discussion" => Some(Self::Board),
            "document" => Some(Self::Document),
            _ => None,
        }
    }

    pub(crate) fn route(self, realm_id: String) -> Route {
        match self {
            Self::Timeline => Route::TimelineRealm { realm_id },
            Self::Board => Route::KanbanRealm { realm_id },
            Self::Document => Route::DocumentRealm { realm_id },
        }
    }

    pub(crate) fn is_available(
        self,
        minimal_ready: bool,
        kanban_ready: bool,
        full_ready: bool,
    ) -> bool {
        match self {
            Self::Timeline => minimal_ready,
            Self::Board => kanban_ready,
            Self::Document => full_ready,
        }
    }
}

pub(crate) fn realm_surface_preference_key(realm_id: &str) -> String {
    format!("realm_surface:{realm_id}")
}

pub(crate) fn load_realm_surface_preference(
    state_store: &LocalStateStore,
    account_key: &str,
    realm_id: &str,
) -> RealmSurface {
    if account_key.trim().is_empty() {
        return RealmSurface::Timeline;
    }

    state_store
        .load_private_data(account_key, &realm_surface_preference_key(realm_id))
        .as_deref()
        .and_then(RealmSurface::from_preference)
        .unwrap_or(RealmSurface::Timeline)
}

pub(crate) fn persist_realm_surface_preference(
    state_store: &mut LocalStateStore,
    account_key: &str,
    realm_id: &str,
    surface: RealmSurface,
) {
    if account_key.trim().is_empty() {
        return;
    }

    state_store.save_private_data(
        account_key,
        realm_surface_preference_key(realm_id),
        surface.preference_value(),
    );
}

pub(crate) fn resolve_realm_surface(
    route: &Route,
    state_store: &LocalStateStore,
    account_key: &str,
    _effective_realm_id: Option<&str>,
) -> Option<RealmSurface> {
    match route {
        Route::Realm { realm_id } => Some(load_realm_surface_preference(
            state_store,
            account_key,
            realm_id,
        )),
        Route::Timeline | Route::TimelineRealm { .. } | Route::TimelineMessage { .. } => {
            Some(RealmSurface::Timeline)
        }
        Route::Chat { .. } | Route::DirectConversation { .. } => None,
        Route::Kanban
        | Route::KanbanRealm { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => Some(RealmSurface::Board),
        Route::Document | Route::DocumentNew | Route::DocumentRealm { .. } => {
            Some(RealmSurface::Document)
        }
        Route::RealmMembers { .. } | Route::RealmAdmin { .. } | Route::RealmAdminSection { .. } => {
            None
        }
        _ => None,
    }
}

pub(crate) fn route_uses_realm_context(route: &Route) -> bool {
    matches!(
        route,
        Route::Realm { .. }
            | Route::Timeline
            | Route::TimelineRealm { .. }
            | Route::TimelineMessage { .. }
            | Route::Chat { .. }
            | Route::DirectConversation { .. }
            | Route::Kanban
            | Route::KanbanRealm { .. }
            | Route::KanbanBoard { .. }
            | Route::KanbanBoardTask { .. }
            | Route::KanbanTask { .. }
            | Route::Document
            | Route::DocumentNew
            | Route::DocumentRealm { .. }
            | Route::RealmMembers { .. }
            | Route::RealmAdmin { .. }
            | Route::RealmAdminSection { .. }
    )
}
