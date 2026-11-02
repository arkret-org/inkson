//! Realm administration and member management over explicit application state.
use std::rc::Rc;

use glory::Scope;

use crate::presentation::{InksonContext, View};
use crate::routes::Route;
mod admin_panel;
mod capabilities;
pub(crate) mod invite_links;
mod members_panel;
mod metadata;
mod organization;
mod policy;
mod section;
pub use organization::{ServerAdminSignal, is_server_admin};

pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
    if let (Some(realm), Some(account)) = (route.realm_id(), context.active_account.get()) {
        let realm = realm.to_owned();
        let authority = account.authority;
        let demand_store = context.state_store.clone();
        let demand_account = authority.clone();
        let demand_realm = realm.clone();
        scope.effect(move || {
            demand_store.read(|store| {
                store.set_product_current_demand(
                    &demand_account,
                    &demand_realm,
                    Some(Vec::new()),
                    vec![arkret_wire::CurrentSelector::RealmAuthorityRoot],
                );
            });
        });
        let store = context.state_store.clone();
        scope
            .on_cleanup(move || {
                store.read(|store| {
                    store.set_product_current_demand(&authority, &realm, None, Vec::new());
                });
            })
            .unwrap_or_else(|error| scope.report_error(error));
    }
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
