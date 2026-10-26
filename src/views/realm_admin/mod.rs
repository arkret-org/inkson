//! Realm administration and member management over explicit application state.
use std::rc::Rc;

use glory::Scope;

use crate::presentation::{InksonContext, View};
use crate::routes::Route;
mod admin_panel;
mod capabilities;
mod members_panel;
mod metadata;
mod organization;
mod policy;
mod section;
pub use organization::{ServerAdminSignal, is_server_admin};

pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
    match route {
        Route::RealmMembers { realm_id } => members_panel::page(scope, context, realm_id),
        Route::RealmAdminSection { realm_id, section } => admin_panel::page(
            scope,
            context,
            realm_id,
            section::RealmAdminSection::from_slug(Some(&section)),
        ),
        Route::RealmAdmin { realm_id } => admin_panel::page(
            scope,
            context,
            realm_id,
            section::RealmAdminSection::Overview,
        ),
        _ => crate::presentation::widgets::plain("Unknown Realm administration route"),
    }
}
