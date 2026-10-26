use super::*;

pub(crate) fn direct_conversation_peer_id(
    contacts: &[crate::models::ContactView],
    realm_id: &str,
    strand_id: &str,
) -> String {
    let matches_route = |summary: &crate::models::DirectConversationSummary| {
        summary.state == arkret_sdk::DirectConversationSummaryState::Found
            && summary.realm_id.as_str() == realm_id
            && summary.main_strand_id.as_str() == strand_id
    };
    for contact in contacts {
        if contact
            .direct_conversation
            .as_ref()
            .is_some_and(matches_route)
        {
            return crate::models::contact_peer_id(contact).to_string();
        }
        if let Some(agent) = contact.contact_agent_projections.iter().find(|agent| {
            agent
                .direct_conversation
                .as_ref()
                .is_some_and(matches_route)
        }) {
            return agent.actor_id.signing_principal_id().to_string();
        }
    }
    String::new()
}

use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CapabilityPhase {
    Ready,
    Pending,
    Missing(Vec<String>),
}

fn route_feature(route: &Route) -> Option<StationFeature> {
    match route {
        Route::Realm { .. }
        | Route::Kanban
        | Route::KanbanRealm { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => Some(StationFeature::Board),
        Route::Chat { .. } | Route::DirectConversation { .. } => Some(StationFeature::Discussion),
        Route::Circles { .. } | Route::CircleDetail { .. } => Some(StationFeature::Circles),
        Route::Setup | Route::SetupSection { .. } => setup_feature(route),
        _ => None,
    }
}

pub(super) fn capability_phase(
    route: &Route,
    description: Option<&ServiceDescribe>,
) -> CapabilityPhase {
    let Some(feature) = route_feature(route) else {
        return CapabilityPhase::Ready;
    };
    let Some(description) = description else {
        return CapabilityPhase::Pending;
    };
    let missing = feature.missing_requirements(Some(description));
    if missing.is_empty() {
        CapabilityPhase::Ready
    } else {
        CapabilityPhase::Missing(missing)
    }
}

pub(super) fn surface(
    scope: &Scope,
    context: Rc<InksonContext>,
    route: Route,
    ui: Rc<super::shell_state::ShellState>,
) -> View {
    let controls = context
        .state_store
        .read(|store| principal_control_realm_ids(&store.load()));
    if let Some(id) = route.realm_id()
        && controls.contains(id)
    {
        return super::manage_pages::principal_control_page(scope, context, Some(id.to_owned()));
    }
    let selection = super::shell_model::resolve_realm_selection(
        route.realm_id(),
        &context.selected_realm_id.get_untracked(),
        &controls,
    );
    let surface = context.state_store.read(|store| {
        resolve_realm_surface(
            &route,
            store,
            &principal_id_owned(context.principal_id.get()),
            selection.effective_realm_id.as_deref(),
        )
    });
    if let Some(surface) = surface
        && !matches!(route, Route::Realm { .. })
        && let Some(realm_id) = selection.effective_realm_id.as_deref()
    {
        let account = principal_id_owned(context.principal_id.get());
        context.state_store.write(|store| {
            if load_realm_surface_preference(store, &account, realm_id) != surface {
                persist_realm_surface_preference(store, &account, realm_id, surface);
            }
        });
    }
    if matches!(route, Route::Onboarding) {
        return crate::views::onboarding::page(scope, context, route);
    }
    if context.active_account.get().is_none() {
        return paragraph(
            "panel-notice panel-notice-error",
            "The active account context is unavailable. Sign in again to continue.",
        );
    }
    let description = context.server_description.get();
    let feature = route_feature(&route);
    if let Some(feature) = feature
        && !feature.ready(description.as_ref())
    {
        return feature_gate_notice(
            scope,
            context,
            feature,
            feature.missing_requirements(description.as_ref()),
            description.is_none(),
        );
    }
    let content = match &route {
        Route::Login | Route::AuthCallback => {
            crate::views::login::page(scope, context.clone(), route.clone())
        }
        Route::Register => crate::views::register::page(scope, context.clone(), route.clone()),
        Route::Dashboard => crate::views::dashboard::page(scope, context.clone(), route.clone()),
        Route::Directory => crate::views::directory::page(scope, context.clone(), route.clone()),
        Route::RealmsManage => super::manage_pages::realms_page(scope, context.clone(), ui),
        Route::PrincipalControl => super::manage_pages::principal_control_page(
            scope,
            context.clone(),
            context
                .state_store
                .read(|store| personal_control_realm_id(&store.load())),
        ),
        Route::ContactsManage => super::manage_pages::contacts_page(scope, context.clone(), ui),
        Route::Contacts => crate::views::contacts::page(scope, context.clone(), route.clone()),
        Route::Setup | Route::SetupSection { .. } => {
            crate::views::setup::page(scope, context.clone(), route.clone())
        }
        Route::RealmMembers { .. } | Route::RealmAdmin { .. } | Route::RealmAdminSection { .. } => {
            crate::views::realm_admin::page(scope, context.clone(), route.clone())
        }
        Route::Circles { .. } | Route::CircleDetail { .. } => {
            crate::views::circles::page(scope, context.clone(), route.clone())
        }
        Route::Realm { realm_id } => crate::views::kanban::page(
            scope,
            context.clone(),
            surface
                .unwrap_or(RealmSurface::Board)
                .route(realm_id.clone()),
        ),
        Route::Kanban
        | Route::KanbanRealm { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => {
            crate::views::kanban::page(scope, context.clone(), route.clone())
        }
        Route::Chat { .. } | Route::DirectConversation { .. } => {
            crate::views::chat::page(scope, context.clone(), route.clone())
        }
        Route::Notifications => {
            crate::views::notifications::page(scope, context.clone(), route.clone())
        }
        Route::Call { .. } => crate::views::call::page(scope, context.clone(), route.clone()),
        Route::Quarantine => crate::views::quarantine::page(scope, context.clone(), route.clone()),
        Route::Applets => {
            if crate::views::applets::applets_enabled() {
                crate::views::applets::page(scope, context.clone(), route.clone())
            } else {
                deferred_feature_gate()
            }
        }
        Route::Search => crate::views::global_search::page(scope, context.clone(), route.clone()),
        _ => crate::views::settings::page(scope, context.clone(), route.clone()),
    };
    Box::new(view().class("realm-body").fill(content))
}
/// Setup overview is local navigation; only its actionable sections need a server.
fn setup_feature(route: &Route) -> Option<StationFeature> {
    match route.setup_section() {
        Some("realms" | "") | None => Some(StationFeature::CreateRealm),
        Some("new-space") => Some(StationFeature::CreateSpace),
        _ => None,
    }
}

#[cfg(test)]
mod feature_routing_tests {
    use super::*;

    #[test]
    fn setup_gates_only_the_selected_workflow() {
        assert_eq!(
            setup_feature(&Route::Setup),
            Some(StationFeature::CreateRealm)
        );
        assert_eq!(
            setup_feature(&Route::SetupSection {
                section: "realms".into()
            }),
            Some(StationFeature::CreateRealm)
        );
        assert_eq!(
            setup_feature(&Route::SetupSection {
                section: "new-space".into()
            }),
            Some(StationFeature::CreateSpace)
        );
        assert_eq!(
            setup_feature(&Route::SetupSection {
                section: "overview".into()
            }),
            None
        );
        assert_eq!(
            setup_feature(&Route::SetupSection {
                section: "unknown".into()
            }),
            None
        );
    }
}
