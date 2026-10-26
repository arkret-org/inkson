//! Sidebar projections and bounded commands over the real account runtime.
#[cfg(test)]
#[path = "sidebar_button_tests.rs"]
mod button_admission_tests;

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::CapabilityActionId;

use crate::models::RealmTreeNode;
use crate::realm_tree::descendant_node_ids;
use crate::state::{ClientLocalState, LocalStateStore};
use crate::views::helpers::short_protocol_id;

pub(super) fn pinned_realm_ids_from_store(store: &LocalStateStore) -> BTreeSet<String> {
    store
        .realm_remarks()
        .into_iter()
        .filter_map(|(realm_id, remark)| remark.pinned.then_some(realm_id))
        .collect()
}

pub(super) fn unread_notification_count(snapshot: &ClientLocalState) -> usize {
    snapshot
        .notification_projection
        .iter()
        .enumerate()
        .filter(|(index, value)| {
            if crate::views::notifications::notification_blocklist_suppressed(value, snapshot) {
                return false;
            }
            let id = value.notification_id();
            let client_state = snapshot.notification_client_state.get(&id);
            let (projection_read, projection_archived) =
                crate::views::notifications::notification_wire_state(value);
            let archived =
                projection_archived || client_state.map(|state| state.archived).unwrap_or(false);
            let read = projection_read
                || client_state.map(|state| state.read).unwrap_or(false)
                || crate::views::notifications::notification_value_read_by_cursor(
                    *index, value, snapshot,
                );
            !archived && !read
        })
        .count()
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct RealmManageRow {
    pub(super) realm_id: String,
    pub(super) display_name: String,
    pub(super) title: String,
    pub(super) encrypted: Option<bool>,
    pub(super) space_count: usize,
}

pub(super) fn principal_control_realm_ids(state: &ClientLocalState) -> BTreeSet<String> {
    let mut ids = state
        .realm_tree_projections
        .iter()
        .filter(|(_, projection)| {
            crate::realm_tree::realm_projection_is_principal_control(projection)
        })
        .map(|(realm_id, _)| realm_id.clone())
        .collect::<BTreeSet<_>>();
    if let Some(evidence) = state.recovery_material_evidence.as_ref() {
        ids.insert(evidence.principal_control_realm_id.to_string());
    }
    ids
}

pub(super) fn navigation_model(
    context: &InksonContext,
    route: &Route,
    query: &str,
) -> super::shell_model::RealmNavigationModel {
    let loaded = context.realm_tree_nodes.get();
    let remembered = context.selected_realm_id.get();
    context.state_store.read(|store| {
        let snapshot = store.load();
        let controls = principal_control_realm_ids(&snapshot);
        let selection =
            super::shell_model::resolve_realm_selection(route.realm_id(), &remembered, &controls);
        let active = selection.effective_realm_id.unwrap_or_default();
        let context_realm = super::route_uses_realm_context(route)
            .then_some(active.as_str())
            .filter(|id| !controls.contains(*id));
        let pinned = pinned_realm_ids_from_store(store);
        let security = store.realm_security_states();
        let remarks = store.realm_remarks();
        super::shell_model::build_realm_navigation(super::shell_model::RealmNavigationInput {
            loaded_nodes: &loaded,
            principal_control_realm_ids: &controls,
            context_realm_id: context_realm,
            active_realm_id: &active,
            pinned_realm_ids: &pinned,
            realm_tree_projections: &snapshot.realm_tree_projections,
            realm_security_states: &security,
            realm_remarks: &remarks,
            collaboration_query: &query.trim().to_ascii_lowercase(),
        })
    })
}

pub(super) fn personal_control_realm_id(state: &ClientLocalState) -> Option<String> {
    state
        .recovery_material_evidence
        .as_ref()
        .map(|evidence| evidence.principal_control_realm_id.to_string())
        .or_else(|| {
            state
                .realm_tree_projections
                .iter()
                .find(|(_, projection)| {
                    crate::realm_tree::realm_projection_control_purpose(projection)
                        == Some("principal_control")
                })
                .map(|(realm_id, _)| realm_id.clone())
        })
}

pub(super) fn sidebar_text_matches_query(normalized_query: &str, values: &[&str]) -> bool {
    normalized_query.is_empty()
        || values
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(normalized_query))
}

/// The Contacts sidebar is a chat surface: only lifecycle-active agents with
/// an effective runtime key belong here. A replacement pairing keeps the
/// existing authorization effective, while bootstrap-pending and expired
/// agents stay in Settings → My Agents. Keeping this filter in one place
/// ensures the initial load and the `owned_agents_rev`-driven reload agree.
fn active_agents_only(
    agents: Vec<arkret_sdk::AgentProjection>,
) -> Vec<arkret_sdk::AgentProjection> {
    agents
        .into_iter()
        .filter(|agent| {
            matches!(agent.lifecycle, arkret_sdk::AgentLifecycleState::Active)
                && matches!(
                    crate::views::agents::model::agent_projection_runtime_state(agent),
                    arkret_sdk::AgentRuntimeState::Ready | arkret_sdk::AgentRuntimeState::Replacing
                )
        })
        .collect()
}

/// Re-pull only the signed-in account's owned agents for the Contacts sidebar,
/// leaving human contacts untouched. Driven by `SessionContext::owned_agents_rev`
/// so a provision/pause/resume/deactivate in Settings → My Agents is reflected
/// in the sidebar without waiting for the user to re-open the tab. A transient
/// error keeps the previously loaded rows rather than clearing the sidebar.
pub(super) fn load_own_agents_for_sidebar(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    base: String,
    api_token: String,
    own_agent_rows: glory::Cage<Vec<arkret_sdk::AgentProjection>>,
    own_agents_loaded: glory::Cage<bool>,
) {
    if api_token.trim().is_empty() {
        own_agent_rows.revise(|current| *current = Vec::new());
        own_agents_loaded.revise(|current| *current = false);
        return;
    }
    own_agents_loaded.revise(|current| *current = true);
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let owner = scope.downgrade();
    if let Err(error) = scope.spawn(async move {
        match crate::transport::auth::with_authed_sdk_client(&base, api_token, |http| async move {
            http.agent_page().await.map_err(anyhow::Error::from)
        })
        .await
        {
            _ if owner.upgrade().is_none() || !context.session_matches(generation, &account) => {}
            Ok(response)
                if owner.upgrade().is_some() && context.session_matches(generation, &account) =>
            {
                own_agent_rows.revise(|current| *current = active_agents_only(response.agents))
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(
                    "failed to reload Agents for Contacts sidebar: {}",
                    err.display_diagnostic()
                );
            }
        }
    }) {
        scope.report_error(error);
    }
}

pub(super) fn load_direct_contacts_and_agents_for_sidebar(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    base: String,
    api_token: String,
    state_store: crate::presentation::SharedStateStore,
    direct_contact_rows: glory::Cage<Vec<crate::models::ContactView>>,
    direct_contacts_loaded: glory::Cage<bool>,
    own_agent_rows: glory::Cage<Vec<arkret_sdk::AgentProjection>>,
    own_agents_loaded: glory::Cage<bool>,
) {
    if api_token.trim().is_empty() {
        state_store.write(|store| store.replace_accepted_human_contacts(&[]));
        direct_contact_rows.revise(|current| *current = Vec::new());
        direct_contacts_loaded.revise(|current| *current = false);
        own_agent_rows.revise(|current| *current = Vec::new());
        own_agents_loaded.revise(|current| *current = false);
        return;
    }

    direct_contacts_loaded.revise(|current| *current = true);
    own_agents_loaded.revise(|current| *current = true);
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let owner = scope.downgrade();
    if let Err(error) = scope.spawn(async move {
        match crate::transport::auth::with_authed_sdk_client(&base, api_token, |http| async move {
            let contacts = crate::transport::account::contacts(&http).await;
            let agents = http.agent_page().await.map_err(anyhow::Error::from);
            Ok((contacts, agents))
        })
        .await
        {
            _ if owner.upgrade().is_none() || !context.session_matches(generation, &account) => {}
            Ok((contacts, agents)) => {
                if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                match contacts {
                    Ok(response) => {
                        if owner.upgrade().is_none()
                            || !context.session_matches(generation, &account)
                        {
                            return;
                        }
                        state_store.write(|store| {
                            store.replace_accepted_human_contacts(&response.contacts)
                        });
                        direct_contact_rows.revise(|current| *current = response.contacts);
                    }
                    Err(err) => {
                        direct_contacts_loaded.revise(|current| *current = false);
                        crate::components::feedback::toast_error(
                            "feedback.contacts_load_failed",
                            vec![],
                            Some(err.to_string()),
                        );
                    }
                }
                match agents {
                    Ok(response)
                        if owner.upgrade().is_some()
                            && context.session_matches(generation, &account) =>
                    {
                        own_agent_rows
                            .revise(|current| *current = active_agents_only(response.agents))
                    }
                    Ok(_) => (),
                    Err(err) => {
                        own_agents_loaded.revise(|current| *current = false);
                        tracing::warn!(error = %err, "failed to load Agents for Contacts sidebar");
                    }
                }
            }
            Err(err) => {
                direct_contacts_loaded.revise(|current| *current = false);
                own_agents_loaded.revise(|current| *current = false);
                crate::components::feedback::toast_error(
                    "feedback.contacts_load_failed",
                    vec![],
                    Some(err.display_diagnostic()),
                );
            }
        }
    }) {
        scope.report_error(error);
    }
}

pub(super) fn load_direct_contacts_for_sidebar(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    base: String,
    api_token: String,
    state_store: crate::presentation::SharedStateStore,
    direct_contact_rows: glory::Cage<Vec<crate::models::ContactView>>,
    direct_contacts_loaded: glory::Cage<bool>,
) {
    if api_token.trim().is_empty() {
        state_store.write(|store| store.replace_accepted_human_contacts(&[]));
        direct_contact_rows.revise(|current| *current = Vec::new());
        direct_contacts_loaded.revise(|current| *current = false);
        return;
    }
    direct_contacts_loaded.revise(|current| *current = true);
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let owner = scope.downgrade();
    if let Err(error) = scope.spawn(async move {
        match crate::transport::auth::with_endpoint_clients(
            &base,
            api_token,
            None,
            |clients| async move { clients.account().contacts().await },
        )
        .await
        {
            _ if owner.upgrade().is_none() || !context.session_matches(generation, &account) => {}
            Ok(response) => {
                if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                state_store
                    .write(|store| store.replace_accepted_human_contacts(&response.contacts));
                direct_contact_rows.revise(|current| *current = response.contacts);
            }
            Err(err) => {
                direct_contacts_loaded.revise(|current| *current = false);
                crate::components::feedback::toast_error(
                    "feedback.contacts_load_failed",
                    vec![],
                    Some(err.display_diagnostic()),
                );
            }
        }
    }) {
        scope.report_error(error);
    }
}

pub(super) fn toggle_sidebar_realm_pin(
    context: std::rc::Rc<crate::presentation::InksonContext>,
    realm_id: String,
    existing: Option<crate::account_data::RealmRemark>,
    next_pinned: bool,
    state_store: crate::presentation::SharedStateStore,
    base_url: String,
    api_token: String,
) {
    let Ok(typed_realm_id) = arkret_sdk::RealmId::new(realm_id.clone()) else {
        return;
    };
    let next = crate::account_data::RealmRemark::with_pinned_preserving_fields(
        typed_realm_id,
        existing.as_ref(),
        next_pinned,
        chrono::Utc::now(),
    );
    state_store.write(|store| store.set_realm_remark(realm_id.clone(), next.clone()));
    crate::components::feedback::toast_success(
        if next_pinned {
            "realm.pinned"
        } else {
            "realm.unpinned"
        },
        vec![],
    );
    crate::views::settings::push_realm_remark_account_data_with_failure_toast(
        context.clone(),
        base_url,
        api_token,
        realm_id,
        next,
    );
}

pub(super) fn toggle_sidebar_contact_pin(
    context: std::rc::Rc<crate::presentation::InksonContext>,
    actor_id: String,
    existing: Option<crate::account_data::ContactRemark>,
    next_pinned: bool,
    state_store: crate::presentation::SharedStateStore,
    base_url: String,
    api_token: String,
) {
    let Ok(actor_id) = crate::mls_api_helpers::principal_core_id(&actor_id) else {
        return;
    };
    let next = crate::account_data::ContactRemark::with_pinned_preserving_fields(
        actor_id.clone(),
        existing.as_ref(),
        next_pinned,
        chrono::Utc::now(),
    );
    state_store.write(|store| store.set_contact_remark(actor_id.to_string(), next.clone()));
    crate::components::feedback::toast_success(
        if next_pinned {
            "contact.pinned"
        } else {
            "contact.unpinned"
        },
        vec![],
    );
    crate::views::settings::push_contact_remark_edit(
        context.clone(),
        base_url,
        api_token,
        actor_id,
        crate::account_data::ContactRemarkEdit::Pinned(next_pinned),
    );
}

pub(super) fn leave_sidebar_realm(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    base_url: String,
    api_token: String,
    realm_id: String,
    principal_id: String,
    state_store: crate::presentation::SharedStateStore,
    realm_tree_nodes: glory::Cage<Vec<RealmTreeNode>>,
    selected_realm_id: glory::Cage<String>,
    sync_cursor: glory::Cage<String>,
) {
    // Realm membership events are authored by the account/principal DID — the
    // server rejects any event whose `actor_id` differs from the authenticated
    // session actor
    // session actor (`actor_session_mismatch`). The local device DID is not the
    // session actor, so it must not be used here.
    let actor_id = principal_id.trim().to_owned();
    if actor_id.is_empty() {
        crate::components::feedback::toast_error("feedback.account_not_connected", vec![], None);
        return;
    }
    let current_nodes = realm_tree_nodes.get();
    let mut ids_to_forget = descendant_node_ids(&current_nodes, &realm_id);
    if ids_to_forget.is_empty() {
        ids_to_forget.push(realm_id.clone());
    }
    let realm_label = short_protocol_id(&realm_id);
    crate::components::feedback::toast_info(
        "feedback.realm_leaving",
        vec![("realm", realm_label.clone())],
    );
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let owner = scope.downgrade();
    if let Err(error) = scope.spawn(async move {
        let realm_for_api = realm_id.clone();
        match crate::transport::auth::with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::realm_write::leave_realm(&sub, &realm_for_api, &actor_id).await
        })
        .await
        {
            _ if owner.upgrade().is_none() || !context.session_matches(generation, &account) => {}
            Ok(_) => {
                if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                let forgotten_ids = ids_to_forget.into_iter().collect::<BTreeSet<_>>();
                for id in &forgotten_ids {
                    state_store.write(|store| store.forget_realm_tree_projection(id));
                    // The shared membership was what authorized reading other
                    // members' global Profiles there; once it is gone those rows
                    // must stop rendering.
                    if let Ok(realm_id) = arkret_sdk::RealmId::new(id.clone()) {
                        crate::identity::contact_profile::forget_realm(&realm_id);
                    }
                }
                realm_tree_nodes
                    .revise(|current| current.retain(|node| !forgotten_ids.contains(&node.id)));
                if forgotten_ids.contains(&selected_realm_id.get()) {
                    selected_realm_id.revise(|current| *current = String::new());
                }
                sync_cursor.revise(|current| *current = String::new());
                crate::components::feedback::toast_success(
                    "feedback.realm_left",
                    vec![("realm", realm_label)],
                );
            }
            Err(err) => crate::components::feedback::toast_error(
                "feedback.realm_leave_failed",
                vec![("realm", realm_label)],
                Some(err.display_diagnostic()),
            ),
        }
    }) {
        scope.report_error(error);
    }
}

/// Per-Realm UI pre-gate for the sidebar row menu's write actions
/// (Add Member / Settings). Presence of a `realm_id` key in the cache means
/// the authz probe has completed; the booleans mirror the server's
/// authoritative decision so the row menu can hide entries the actor cannot
/// use. This is advisory only — the server still makes the real call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SidebarRowRealmPerms {
    pub(super) can_add_member: bool,
    pub(super) can_settings: bool,
}

/// Lazily probe whether `actor` may add members (`ak.invite.create`) or edit
/// settings (`ak.realm.profile`) on `realm_id`, caching the verdict in
/// `perms_cache`.
///
/// Triggered when a sidebar row's kebab menu opens, so at most two authz
/// requests are issued for the single Realm whose menu is open — never the
/// `2*N` that eager per-row probing on every sidebar render would cost.
/// Fail-closed: a transport error or a non-allow body both leave the write
/// actions hidden, and we still cache that verdict so we don't re-probe a
/// Realm the actor plainly cannot manage on every menu open.
pub(super) fn ensure_sidebar_row_perms(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    base_url: String,
    api_token: String,
    actor: String,
    realm_id: String,
    perms_cache: glory::Cage<BTreeMap<String, SidebarRowRealmPerms>>,
) {
    if api_token.trim().is_empty() || actor.trim().is_empty() || realm_id.trim().is_empty() {
        return;
    }
    if perms_cache.with(|store| store.contains_key(&realm_id)) {
        return;
    }
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let owner = scope.downgrade();
    if let Err(error) = scope.spawn(async move {
        let perms = match crate::transport::auth::authed_api_with_sync(&base_url, api_token, None) {
            Ok(api) => {
                let invite = async {
                    crate::transport::realm_read::authz_check(
                        &api.sdk_http_client()?,
                        &actor,
                        CapabilityActionId::INVITE_CREATE,
                        &realm_id,
                    )
                    .await
                }
                .await;
                let settings = async {
                    crate::transport::realm_read::authz_check(
                        &api.sdk_http_client()?,
                        &actor,
                        CapabilityActionId::REALM_PROFILE,
                        &realm_id,
                    )
                    .await
                }
                .await;
                SidebarRowRealmPerms {
                    can_add_member: invite
                        .as_ref()
                        .map(crate::transport::realm_read::authz_allowed)
                        .unwrap_or(false),
                    can_settings: settings
                        .as_ref()
                        .map(crate::transport::realm_read::authz_allowed)
                        .unwrap_or(false),
                }
            }
            Err(_) => SidebarRowRealmPerms::default(),
        };
        if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
            return;
        }
        perms_cache.revise(|store| store.insert(realm_id, perms));
    }) {
        scope.report_error(error);
    }
}

pub(super) fn delete_sidebar_contact(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    base_url: String,
    api_token: String,
    peer: String,
    state_store: crate::presentation::SharedStateStore,
    direct_contact_rows: glory::Cage<Vec<crate::models::ContactView>>,
    direct_contacts_loaded: glory::Cage<bool>,
) {
    let peer_label = serde_json::from_str::<arkret_sdk::ActorId>(&peer)
        .map(|actor| match actor {
            arkret_sdk::ActorId::Account { account_id } => state_store
                .read(|store| crate::views::helpers::account_display_label(store, &account_id)),
            arkret_sdk::ActorId::Service { service_id } => state_store.read(|store| {
                crate::views::helpers::actor_display_label(store, service_id.as_str())
            }),
            arkret_sdk::ActorId::Realm { realm_actor_id } => state_store.read(|store| {
                crate::views::helpers::actor_display_label(store, &realm_actor_id.to_string())
            }),
        })
        .unwrap_or_else(|_| crate::views::helpers::short_protocol_id(&peer));
    crate::components::feedback::toast_info(
        "feedback.contact_deleting",
        vec![("name", peer_label.clone())],
    );
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let owner = scope.downgrade();
    if let Err(error) = scope.spawn(async move {
        let peer_for_api = peer.clone();
        match crate::transport::auth::with_authed_sdk_client(
            &base_url,
            api_token,
            |http| async move {
                crate::transport::account::tombstone_contact(&http, &peer_for_api, false).await
            },
        )
        .await
        {
            _ if owner.upgrade().is_none() || !context.session_matches(generation, &account) => {}
            Ok(_) => {
                if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                let next_rows: Vec<_> = direct_contact_rows
                    .get()
                    .into_iter()
                    .filter(|row| row.peer.contact_actor_id().to_string() != peer)
                    .collect();
                state_store.write(|store| store.replace_accepted_human_contacts(&next_rows));
                direct_contact_rows.revise(|current| *current = next_rows);
                direct_contacts_loaded.revise(|current| *current = true);
                crate::components::feedback::toast_success(
                    "feedback.contact_deleted",
                    vec![("name", peer_label)],
                );
            }
            Err(err) => crate::components::feedback::toast_error(
                "feedback.contact_delete_failed",
                vec![("name", peer_label)],
                Some(err.display_diagnostic()),
            ),
        }
    }) {
        scope.report_error(error);
    }
}

/// One-shot push-token provider bootstrap.
///
/// Runs once on first App render. On wasm32 we install
/// `WebPushTokenProvider::new()` (drives the service-worker +
/// `pushManager.subscribe` path described in `push.rs::WebPushTokenProvider`).
/// On native builds we install `FcmPushTokenProvider` / `ApnsPushTokenProvider`.
/// The host adapter supplies the actual OS token through
/// `set_fcm_push_token` / `set_apns_push_token` after Firebase/APNs returns
/// it; local dev can inject the same token via env vars. Subsequent renders
/// short-circuit via `OnceLock` semantics inside `set_push_token_provider`.
pub(super) fn ensure_default_push_token_provider() {
    if crate::push::push_token_provider().is_some() {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::WebPushTokenProvider::new(),
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "android"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::ApnsPushTokenProvider,
        ));
    }
    #[cfg(all(
        not(target_arch = "wasm32"),
        not(target_os = "android"),
        not(target_os = "ios")
    ))]
    {
        // Desktop / server builds: install the FCM provider as the
        // safe default. It reads `INKSON_FCM_PUSH_TOKEN`,
        // `FCM_PUSH_TOKEN`, or `CHASK_PUSH_KEY` for local bridge
        // testing, and otherwise reports "no token" without emitting a
        // placeholder to the gateway.
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
}

use std::rc::Rc;

use glory::prelude::*;
use glory::render::{
    DragPhase, Event, EventKind, FocusMode, Orientation, RangeCommand, RangeValue, Role,
    SemanticId, Semantics,
};

use super::session_shell::{action, block, icon_action, nav};
use super::shell_state::ShellState;
use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;

fn icon_link(
    context: Rc<InksonContext>,
    route: Route,
    class: impl Into<Lotus<String>>,
    label: impl Into<Lotus<String>>,
    icon: &str,
) -> View {
    Box::new(
        internal_link()
            .target(route.to_string())
            .class(class)
            .name(label)
            .fill(crate::components::ui_icon(icon))
            .on(EventKind::Activate, move |_| {
                context.navigate(route.clone())
            }),
    )
}

fn load_sidebar_contacts(scope: &Scope, context: &Rc<InksonContext>, ui: &Rc<ShellState>) {
    if ui.contacts_loaded.get_untracked() || context.token.get_untracked().trim().is_empty() {
        return;
    }
    load_direct_contacts_and_agents_for_sidebar(
        scope,
        context.clone(),
        context.base_url.get_untracked(),
        context.token.get_untracked(),
        context.state_store.clone(),
        context.contact_rows,
        ui.contacts_loaded,
        ui.agents,
        ui.agents_loaded,
    );
}

pub(super) fn sidebar(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let tab = ui.tab;
    let paging = reactive(
        scope.bond({
            let context = context.clone();
            move || {
                let _ = context.state_revision.get();
                !context.token.get().trim().is_empty()
                    && context
                        .state_store
                        .read(|store| store.sync_realm_list_after().is_some())
            }
        }),
        {
            let context = context.clone();
            move |scope, available| {
                if !available {
                    return empty();
                }
                action(
                    "sidebar-toolbar-action",
                    context.translated(scope, "directory.load_more_realms"),
                    {
                        let context = context.clone();
                        move || {
                            context
                                .state_store
                                .write(|store| store.request_next_sync_realm_list_page())
                        }
                    },
                )
            }
        },
    );
    let controls = reactive_distinct(ui.collapsed, {
        let context = context.clone();
        let ui = ui.clone();
        move |scope, collapsed| {
            if collapsed {
                return empty();
            }
            let direct_context = context.clone();
            let direct_ui = ui.clone();
            let weak = scope.downgrade();
            let tabs = block(
                "sidebar-scope-toggle realm-tabs",
                vec![
                    Box::new(
                        sapid::button()
                            .unstyled()
                            .class(scope.bond(move || {
                                if tab.get() == "collaboration" {
                                    "scope-chip active"
                                } else {
                                    "scope-chip"
                                }
                                .to_owned()
                            }))
                            .label(context.translated(scope, "nav.collaboration"))
                            .on_press(move || tab.revise(|value| *value = "collaboration".into())),
                    ) as View,
                    Box::new(
                        sapid::button()
                            .unstyled()
                            .class(scope.bond(move || {
                                if tab.get() == "direct" {
                                    "scope-chip active"
                                } else {
                                    "scope-chip"
                                }
                                .to_owned()
                            }))
                            .label(context.translated(scope, "nav.contacts"))
                            .on_press(move || {
                                tab.revise(|value| *value = "direct".into());
                                if let Some(scope) = weak.upgrade() {
                                    load_sidebar_contacts(&scope, &direct_context, &direct_ui);
                                }
                            }),
                    ) as View,
                ],
            );
            let toolbar = reactive_distinct(tab, {
                let context = context.clone();
                let ui = ui.clone();
                move |scope, tab| {
                    let direct = tab == "direct";
                    let (value, label) = if direct {
                        (ui.contact_query, "sidebar.search_contacts")
                    } else {
                        (ui.realm_query, "sidebar.search_realms")
                    };
                    let weak = scope.downgrade();
                    let search_context = context.clone();
                    let search_ui = ui.clone();
                    let hint = reactive_distinct(scope.bond(move || value.get().is_empty()), {
                        let context = context.clone();
                        move |scope, empty_value| {
                            if empty_value {
                                paragraph(
                                    "sidebar-search-placeholder",
                                    context.translated(scope, label),
                                )
                            } else {
                                empty()
                            }
                        }
                    });
                    let search = block(
                        "sidebar-tab-search",
                        vec![
                            input_field(
                                context.clone(),
                                format!("sidebar-{tab}-query"),
                                context.translated(scope, label),
                                value,
                                Purpose::Text,
                            ),
                            icon_action(
                                "sidebar-toolbar-action sidebar-tab-search-submit",
                                context.translated(scope, "sidebar.search"),
                                "search",
                                move || {
                                    if direct && let Some(scope) = weak.upgrade() {
                                        load_sidebar_contacts(&scope, &search_context, &search_ui);
                                    }
                                },
                            ),
                            hint,
                        ],
                    );
                    let add = if direct {
                        Route::Contacts
                    } else {
                        Route::SetupSection {
                            section: "realms".into(),
                        }
                    };
                    let manage = if direct {
                        Route::ContactsManage
                    } else {
                        Route::RealmsManage
                    };
                    block(
                        "sidebar-tab-toolbar",
                        vec![
                            search,
                            icon_link(
                                context.clone(),
                                add,
                                if direct {
                                    "sidebar-toolbar-action sidebar-toolbar-link add-contact-cta"
                                } else {
                                    "sidebar-toolbar-action sidebar-toolbar-link add-realm-cta"
                                },
                                context.translated(
                                    scope,
                                    if direct {
                                        "contacts.empty_add"
                                    } else {
                                        "setup.new_realm"
                                    },
                                ),
                                if direct { "user-plus" } else { "plus" },
                            ),
                            icon_link(
                                context.clone(),
                                manage,
                                "sidebar-toolbar-action sidebar-toolbar-link manage-home-link",
                                context.translated(
                                    scope,
                                    if direct {
                                        "manage.contacts_title"
                                    } else {
                                        "manage.realms_title"
                                    },
                                ),
                                "home",
                            ),
                        ],
                    )
                }
            });
            block("sidebar-tab-controls", vec![tabs, toolbar])
        }
    });
    let rows = reactive_distinct(tab, {
        let context = context.clone();
        let ui = ui.clone();
        move |scope, tab| {
            if tab == "direct" {
                contacts(scope, context.clone(), ui.clone())
            } else {
                realm_rows(scope, context.clone(), ui.clone())
            }
        }
    });
    let description = scope.bond({
        let context = context.clone();
        move || crate::config::normalize_server_url(&context.base_url.get())
    });
    let server_menu_source = scope.bond({
        let ui = ui.clone();
        move || (ui.server_open.get(), ui.collapsed.get())
    });
    let server = reactive(server_menu_source, {
        let context = context.clone();
        let ui = ui.clone();
        move |scope, (open, collapsed)| {
            if !open || collapsed {
                return empty();
            }
            let config = context.config_store.get().load();
            let base = context.base_url.get();
            block(
                "server-switch-menu",
                vec![block(
                    "server-option-list",
                    super::server_options_for(&base, &config.stations)
                        .into_iter()
                        .map(|url| {
                            let current = crate::config::same_server_url(&url, &base);
                            let weak = scope.downgrade();
                            let context = context.clone();
                            let ui = ui.clone();
                            let mut content = vec![Box::new(
                                text()
                                    .class("server-option-text server-option-main mono")
                                    .content(url.clone()),
                            ) as View];
                            if current {
                                content.push(Box::new(
                                    text().class("pill muted xs").content("current"),
                                ));
                            }
                            Box::new(
                                sapid::button()
                                    .unstyled()
                                    .class(if current {
                                        "server-option active"
                                    } else {
                                        "server-option"
                                    })
                                    .name(format!("Switch to {url}"))
                                    .fill(content)
                                    .on_press(move || {
                                        ui.server_open.revise(|value| *value = false);
                                        if let Some(scope) = weak.upgrade() {
                                            super::connection_handlers::switch_server_and_connect(
                                                &scope,
                                                url.clone(),
                                                context.clone(),
                                            );
                                        }
                                    }),
                            ) as View
                        })
                        .collect(),
                )],
            )
        }
    });
    let open = ui.server_open;
    let disclosure = scope.bond(move || {
        Some(Box::new(Semantics {
            expanded: Some(open.get()),
            ..Default::default()
        }))
    });
    let chevron = glory::ui::when(open, || {
        crate::components::icons::ui_icon_with_class("chevron-up", "ui-icon server-switch-state")
    })
    .otherwise(|| {
        crate::components::icons::ui_icon_with_class("chevron-down", "ui-icon server-switch-state")
    });
    let server_toggle = {
        let ui = ui.clone();
        Box::new(
            glory::ui::button()
                .class("server-switch-button")
                .name("Switch server")
                .semantics(disclosure)
                .fill(vec![
                    crate::components::icons::ui_icon_with_class(
                        "server",
                        "ui-icon server-switch-icon",
                    ),
                    Box::new(
                        text()
                            .class("server-switch-title server-option-main")
                            .content(description),
                    ),
                    Box::new(chevron),
                ])
                .on(EventKind::Activate, move |_| {
                    ui.server_open.revise(|value| *value = !*value);
                    ui.account_open.revise(|value| *value = false);
                }),
        ) as View
    };
    let brand = {
        let context = context.clone();
        Box::new(
            internal_link()
                .class("brand")
                .target(Route::Dashboard.to_string())
                .name(context.translated(scope, "app.brand.home"))
                .fill(vec![
                    paragraph("logo", "⌘"),
                    block(
                        "product-meta",
                        vec![paragraph("product-name", "Inkson | Arkret")],
                    ),
                ])
                .on(EventKind::Activate, move |_| {
                    context.navigate(Route::Dashboard)
                }),
        ) as View
    };
    let route = context.route;
    let home = Box::new(
        internal_link()
            .target(Route::Dashboard.to_string())
            .class(scope.bond(move || {
                if route.get() == Route::Dashboard {
                    "sidebar-nav-item is-active"
                } else {
                    "sidebar-nav-item"
                }
                .to_owned()
            }))
            .fill(vec![
                block("sidebar-nav-icon", vec![crate::components::ui_icon("home")]),
                paragraph("grow", context.translated(scope, "nav.dashboard")),
            ])
            .on(EventKind::Activate, {
                let context = context.clone();
                move |_| context.navigate(Route::Dashboard)
            }),
    ) as View;
    let sidebar_id = match SemanticId::new("application-sidebar") {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    Box::new(
        view()
            .class("sidebar")
            .role(Role::Navigation)
            .name(context.translated(scope, "app.nav.main_navigation"))
            .semantics(Some(Box::new(Semantics {
                id: Some(sidebar_id),
                ..Default::default()
            })))
            .fill(vec![
                resize_handle(scope, context.clone(), ui.clone()),
                block("sidebar-header", vec![brand]),
                block("server-switch", vec![server_toggle, server]),
                block("sidebar-nav-group", vec![home]),
                block(
                    "sidebar-nav-group realm-tab-group",
                    vec![paging, controls, rows],
                ),
            ]),
    )
}

fn resize_handle(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let width = ui.width;
    let resizing = ui.resizing;
    let (id, controls) = match (
        SemanticId::new("sidebar-resize"),
        SemanticId::new("application-sidebar"),
    ) {
        (Ok(id), Ok(controls)) => (id, controls),
        (Err(error), _) | (_, Err(error)) => {
            scope.report_error(error);
            return empty();
        }
    };
    let semantics = scope.bond(move || {
        Some(Box::new(Semantics {
            id: Some(id.clone()),
            splitter: Some(RangeValue {
                min: super::MIN_SIDEBAR_WIDTH,
                max: super::MAX_SIDEBAR_WIDTH,
                value: width.get(),
            }),
            separator_axis: Some(Orientation::Vertical),
            controls: Some(controls.clone()),
            ..Default::default()
        }))
    });
    let drag_context = context.clone();
    Box::new(
        view()
            .class("sidebar-resize-handle")
            .role(Role::Separator)
            .name("Resize navigation")
            .focus(FocusMode::TabStop)
            .semantics(semantics)
            .on(EventKind::Range, move |event| {
                if let Event::Range { command, .. } = event {
                    let old = width.get_untracked();
                    let next = super::clamp_sidebar_width(match command {
                        RangeCommand::Decrease => old - 4.0,
                        RangeCommand::Increase => old + 4.0,
                        RangeCommand::PageDecrease => old - 40.0,
                        RangeCommand::PageIncrease => old + 40.0,
                        RangeCommand::Minimum => super::MIN_SIDEBAR_WIDTH,
                        RangeCommand::Maximum => super::MAX_SIDEBAR_WIDTH,
                        RangeCommand::Set(value) => value,
                    });
                    width.revise(|value| *value = next);
                    context
                        .state_store
                        .write(|store| super::save_sidebar_width_preference(store, next));
                }
            })
            .on(EventKind::Drag, move |event| {
                if let Event::Drag { phase, x, .. } = event {
                    match phase {
                        DragPhase::Start | DragPhase::Move => {
                            resizing.revise(|value| *value = true);
                            width.revise(|value| *value = super::clamp_sidebar_width(x));
                        }
                        DragPhase::Drop | DragPhase::Cancel => {
                            resizing.revise(|value| *value = false);
                            drag_context.state_store.write(|store| {
                                super::save_sidebar_width_preference(store, width.get_untracked())
                            });
                        }
                    }
                }
            }),
    )
}
fn realm_link_security_hint(
    _scope: &Scope,
    key: String,
    description: String,
    link: glory::ui::Link,
) -> View {
    #[cfg(target_arch = "wasm32")]
    {
        let mut link = Some(link);
        Box::new(
            sapid::tooltip(key)
                .label(description.clone())
                .text(description)
                .target(move |target| target.link(link.take().expect("one Realm hint target"))),
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let id = match glory::render::SemanticId::new(format!("{key}-description")) {
            Ok(id) => id,
            Err(error) => {
                _scope.report_error(error);
                return empty();
            }
        };
        Box::new(
            glory::ui::group().fill((
                link.semantics(Some(Box::new(glory::render::Semantics {
                    described_by: Some(id.clone()),
                    ..Default::default()
                }))),
                glory::ui::text()
                    .class("sr-only realm-security-description")
                    .content(description)
                    .semantics(Some(Box::new(glory::render::Semantics {
                        id: Some(id),
                        ..Default::default()
                    }))),
            )),
        )
    }
}
fn realm_rows(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let source = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            (
                context.realm_tree_nodes.get(),
                context.state_revision.get(),
                context.route.get(),
                ui.realm_query.get(),
                context.locale.get(),
                context.selected_realm_id.get(),
            )
        }
    });
    reactive(source, move |scope, (_, _, route, query, ..)| {
        let model = navigation_model(&context, &route, &query);
        let active_realm_id = model.active_projection_realm_id;
        let nodes = model.collaboration_nodes;
        let items = model.filtered_realm_tree;
        let pinned = context.state_store.read(pinned_realm_ids_from_store);
        let mut rows = Vec::new();
        for item in items {
            let node = item.node;
            let id = node.id.clone();
            let target = node.projection_realm_id().to_owned();
            let remark = context.state_store.read(|store| store.realm_remark(&id));
            let label = remark
                .as_ref()
                .map(|remark| remark.display_name(&node.title).to_owned())
                .unwrap_or_else(|| node.title.clone());
            let encrypted = context.state_store.read(|store| {
                store
                    .realm_security_states()
                    .get(&target)
                    .copied()
                    .flatten()
            });
            let icon = if node.kind == crate::models::RealmTreeNodeKind::Space {
                "folder"
            } else {
                match encrypted {
                    Some(true) => "lock",
                    Some(false) => "unlock",
                    None => "help-circle",
                }
            };
            let class =
                if node.kind == crate::models::RealmTreeNodeKind::Realm && active_realm_id == id {
                    "sidebar-nav-item realm-tree-item is-active sidebar-row-main"
                } else {
                    "sidebar-nav-item realm-tree-item sidebar-row-main"
                };
            let mut badges = Vec::new();
            if remark
                .as_ref()
                .is_some_and(|remark| !remark.local_name.is_empty())
            {
                badges.push(paragraph(
                    "pill muted xs",
                    context.translated(scope, "app.sidebar.remark"),
                ));
            }
            if pinned.contains(&id) {
                badges.push(block(
                    "pill muted xs realm-pin-badge",
                    vec![crate::components::ui_icon("pin")],
                ));
            }
            if item.descendant_count > 0 && node.kind == crate::models::RealmTreeNodeKind::Realm {
                badges.push(paragraph(
                    "pill muted xs",
                    item.descendant_count.to_string(),
                ));
            } else {
                badges.push(paragraph(
                    "pill muted xs",
                    context.translated(
                        scope,
                        if node.kind == crate::models::RealmTreeNodeKind::Realm {
                            "friendly.realm"
                        } else {
                            "friendly.space"
                        },
                    ),
                ));
            }
            let icon_class = if node.kind == crate::models::RealmTreeNodeKind::Realm {
                match encrypted {
                    Some(true) => "sidebar-nav-icon realm-security-secure",
                    Some(false) => "sidebar-nav-icon realm-security-unsafe",
                    None => "sidebar-nav-icon",
                }
            } else {
                "sidebar-nav-icon"
            };
            let mut content = vec![
                block(icon_class, vec![crate::components::ui_icon(icon)]),
                paragraph("grow truncate", label.clone()),
            ];
            content.extend(badges);
            let description = if node.kind == crate::models::RealmTreeNodeKind::Realm {
                match encrypted {
                    Some(true) => "Encrypted Realm".to_owned(),
                    Some(false) => "Unencrypted Realm".to_owned(),
                    None => context.tr("realm.security_unknown_title"),
                }
            } else {
                context.tr("friendly.space")
            };
            use sha2::Digest;
            let hint_key = format!(
                "realm-security-{}",
                &hex::encode(sha2::Sha256::digest(id.as_bytes()))[..24]
            );
            let main = realm_link_security_hint(
                scope,
                hint_key,
                description,
                internal_link()
                    .class(format!("{class} sidebar-row-depth-{}", item.depth.min(32)))
                    .target(
                        Route::Realm {
                            realm_id: target.clone(),
                        }
                        .to_string(),
                    )
                    .name(label.clone())
                    .fill(content)
                    .on(EventKind::Activate, {
                        let context = context.clone();
                        let realm = target.clone();
                        move |_| {
                            context
                                .selected_realm_id
                                .revise(|value| *value = realm.clone());
                            context.navigate(Route::Realm {
                                realm_id: realm.clone(),
                            });
                        }
                    }),
            );
            let menu_key = format!("realm:{id}");
            let weak = scope.downgrade();
            let show_context = context.clone();
            let show_ui = ui.clone();
            let key = menu_key.clone();
            let realm = target.clone();
            let toggle = icon_action(
                "sidebar-row-menu-button",
                "Realm actions",
                "more-horizontal",
                move || {
                    show_ui.row_menu.revise(|value| {
                        *value = if value.as_ref() == Some(&key) {
                            None
                        } else {
                            Some(key.clone())
                        }
                    });
                    if let Some(scope) = weak.upgrade() {
                        ensure_sidebar_row_perms(
                            &scope,
                            show_context.clone(),
                            show_context.base_url.get(),
                            show_context.token.get(),
                            super::principal_id_owned(show_context.principal_id.get()),
                            realm.clone(),
                            show_ui.row_perms,
                        );
                    }
                },
            );
            let source = scope.bond({
                let ui = ui.clone();
                move || (ui.row_menu.get(), ui.row_perms.get())
            });
            let menu_context = context.clone();
            let menu_ui = ui.clone();
            let realm_node = node.clone();
            let menu = reactive(source, move |scope, (open, perms)| {
                if open.as_deref() != Some(menu_key.as_str()) {
                    return empty();
                }
                let mut actions = Vec::new();
                if realm_node.kind == crate::models::RealmTreeNodeKind::Realm {
                    let context = menu_context.clone();
                    let id = id.clone();
                    let existing = remark.clone();
                    let next = !existing.as_ref().is_some_and(|remark| remark.pinned);
                    actions.push(action(
                        "sidebar-row-menu-item",
                        context.translated(scope, if next { "realm.pin" } else { "realm.unpin" }),
                        move || {
                            toggle_sidebar_realm_pin(
                                context.clone(),
                                id.clone(),
                                existing.clone(),
                                next,
                                context.state_store.clone(),
                                context.base_url.get(),
                                context.token.get(),
                            )
                        },
                    ));
                }
                let context = menu_context.clone();
                let parent = realm_node.id.clone();
                let home = target.clone();
                let selected = menu_ui.row_menu;
                actions.push(action(
                    "sidebar-row-menu-item",
                    menu_context.translated(scope, "setup.space.new_space"),
                    move || {
                        context
                            .selected_realm_id
                            .revise(|value| *value = home.clone());
                        context
                            .new_space_context_node
                            .revise(|value| *value = parent.clone());
                        selected.revise(|value| *value = None);
                        context.navigate(Route::SetupSection {
                            section: "new-space".into(),
                        });
                    },
                ));
                let permission = perms.get(&target).copied().unwrap_or_default();
                if permission.can_add_member {
                    actions.push(nav(
                        menu_context.clone(),
                        Route::RealmMembers {
                            realm_id: target.clone(),
                        },
                        "sidebar-row-menu-item",
                        menu_context.translated(scope, "realm.add_member"),
                        "users",
                    ));
                }
                if permission.can_settings {
                    actions.push(nav(
                        menu_context.clone(),
                        Route::RealmAdmin {
                            realm_id: target.clone(),
                        },
                        "sidebar-row-menu-item",
                        menu_context.translated(scope, "realm.settings"),
                        "settings",
                    ));
                }
                actions.push(nav(
                    menu_context.clone(),
                    Route::Circles {
                        realm_id: target.clone(),
                    },
                    "sidebar-row-menu-item",
                    menu_context.translated(scope, "route.circles"),
                    "users",
                ));
                if realm_node.kind == crate::models::RealmTreeNodeKind::Realm {
                    let pending = menu_ui.pending_leave;
                    let id = target.clone();
                    let name = label.clone();
                    actions.push(action(
                        "sidebar-row-menu-item danger",
                        menu_context.translated(scope, "realm_admin.leave_realm"),
                        move || pending.revise(|value| *value = Some((id.clone(), name.clone()))),
                    ));
                }
                block("sidebar-row-menu-panel", actions)
            });
            rows.push(block(
                "sidebar-row",
                vec![main, block("sidebar-row-menu-host", vec![toggle, menu])],
            ));
        }
        if rows.is_empty() {
            rows.push(block(
                "sidebar-nav-item is-dim",
                vec![
                    crate::components::ui_icon("folder"),
                    plain(context.translated(
                        scope,
                        if nodes.is_empty() {
                            "sidebar.realms_empty"
                        } else {
                            "sidebar.realms_no_results"
                        },
                    )),
                ],
            ));
            rows.push(paragraph("sidebar-nav-meta", context.connection_status));
        }
        block("realm-tree-list", rows)
    })
}
fn direct_button(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<ShellState>,
    label: String,
    seed: String,
    blob: Option<String>,
    key: String,
    target: super::direct_open::DirectConversationTarget,
    found: Option<crate::models::DirectConversationSummary>,
    enabled: bool,
    class: &str,
) -> View {
    let opening = ui.opening;
    let available = scope.bond(move || opening.get().is_none());
    let own_key = key.clone();
    let busy = scope.bond(move || opening.get().as_deref() == Some(own_key.as_str()));
    let is_agent = !matches!(
        &target,
        super::direct_open::DirectConversationTarget::Peer { .. }
    );
    let identity = match &target {
        super::direct_open::DirectConversationTarget::Peer { peer_id } => {
            match serde_json::from_str::<arkret_sdk::ActorId>(peer_id) {
                Ok(actor) => match actor.as_account_id() {
                    Some(account) => format!(
                        "Principal: {} · Station: {}",
                        account.principal_id, account.station_id
                    ),
                    None => peer_id.clone(),
                },
                Err(_) => peer_id.clone(),
            }
        }
        super::direct_open::DirectConversationTarget::OwnedAgent {
            agent_id,
            controller_principal_id,
        } => format!("Agent: {agent_id} · Controller: {controller_principal_id}"),
        super::direct_open::DirectConversationTarget::ContactAgent {
            agent_id,
            controller,
        } => format!("Agent: {agent_id} · Controller: {controller}"),
    };
    use sha2::Digest;
    let identity_id = match SemanticId::new(format!(
        "direct-recipient-{}",
        hex::encode(sha2::Sha256::digest(key.as_bytes()))
    )) {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    let described_by = identity_id.clone();
    let semantics = scope.bond(move || {
        Some(Box::new(Semantics {
            busy: Some(busy.get()),
            described_by: Some(described_by.clone()),
            ..Default::default()
        }))
    });
    let name = scope.bond({
        let label = label.clone();
        let context = context.clone();
        move || {
            if busy.get() {
                format!("Opening chat with {label}")
            } else if enabled {
                format!("Chat with {label}")
            } else {
                context.tr("direct.unavailable")
            }
        }
    });
    let weak = scope.downgrade();
    let avatar = crate::components::generated_avatar::identity_avatar_inline(
        scope,
        context.clone(),
        crate::components::IdentityAvatarProps {
            seed,
            alt_text: label.clone(),
            blob_ref: blob,
            class: if is_agent {
                "sidebar-nav-icon contact-sidebar-agent-avatar avatar-img"
            } else {
                "sidebar-nav-icon contact-sidebar-user-avatar avatar-img"
            }
            .into(),
            test_id: None,
        },
    );
    let mut children: Vec<View> = vec![
        avatar,
        Box::new(text().class("grow truncate").content(label)),
    ];
    if is_agent {
        let context = context.clone();
        children.push(Box::new(
            text()
                .class("pill muted xs contact-sidebar-agent-badge")
                .content(scope.bond(move || {
                    context.tr(if busy.get() {
                        "app.sidebar.opening"
                    } else {
                        "app.sidebar.agent_badge"
                    })
                })),
        ));
    } else if let super::direct_open::DirectConversationTarget::Peer { peer_id } = &target
        && let Some(contact) = context
            .contact_rows
            .get_untracked()
            .iter()
            .find(|contact| contact.peer.contact_actor_id().to_string() == *peer_id)
    {
        let state = crate::models::contact_state_wire(contact.state).to_owned();
        let state_context = context.clone();
        children.push(Box::new(
            text()
                .class("pill muted xs contact-sidebar-state")
                .content(scope.bond(move || {
                    if busy.get() {
                        state_context.tr("app.sidebar.opening")
                    } else {
                        state.clone()
                    }
                })),
        ));
        if contact
            .bidirectional_scopes
            .contains(&arkret_sdk::contact_operations::ContactScope::DirectMessage)
        {
            children.push(Box::new(
                text()
                    .class("pill muted xs contact-sidebar-direct-badge")
                    .content(context.translated(scope, "app.sidebar.direct_badge")),
            ));
        }
        let principal = crate::models::contact_peer_id(contact).to_string();
        if let Some(remark) = context
            .state_store
            .read(|store| store.contact_remark(&principal))
        {
            if !remark.petname.trim().is_empty() {
                children.push(Box::new(
                    text()
                        .class("pill muted xs contact-sidebar-remark-badge")
                        .content(context.translated(scope, "app.sidebar.remark")),
                ));
            }
            if remark.pinned {
                children.push(Box::new(
                    text()
                        .class("pill muted xs realm-pin-badge contact-sidebar-pinned-badge")
                        .content(context.translated(scope, "contact.pinned")),
                ));
            }
        }
    }
    // The visible label remains short; assistive technology retains the complete recipient
    // identity.
    children.push(Box::new(
        text()
            .class("sr-only direct-recipient-identity")
            .content(identity)
            .semantics(Some(Box::new(Semantics {
                id: Some(identity_id),
                ..Default::default()
            }))),
    ));
    Box::new(
        glory::ui::button()
            .class(class.to_owned())
            .name(name)
            .semantics(semantics)
            .enabled(available)
            .fill(children)
            .on(EventKind::Activate, move |_| {
                if opening.get_untracked().is_some() {
                    return;
                }
                if !enabled {
                    crate::components::feedback::toast_info("direct.unavailable", vec![]);
                    return;
                }
                if let Some(summary) = &found
                    && summary.state == arkret_sdk::DirectConversationSummaryState::Found
                {
                    context.navigate(Route::DirectConversation {
                        realm_id: summary.realm_id.to_string(),
                        strand_id: summary.main_strand_id.to_string(),
                    });
                    return;
                }
                if let Some(scope) = weak.upgrade() {
                    opening.revise(|value| *value = Some(key.clone()));
                    super::direct_open::open_direct_conversation(
                        &scope,
                        context.clone(),
                        context.base_url.get(),
                        context.token.get(),
                        context.state_store.clone(),
                        opening,
                        target.clone(),
                    );
                }
            }),
    )
}
fn contacts(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let source = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            (
                context.contact_rows.get(),
                ui.agents.get(),
                ui.contact_query.get(),
                ui.expanded_contacts.get(),
                context.principal_id.get(),
                context.account_primary_handle.get(),
                context.token.get(),
                ui.avatar.get(),
                context.state_revision.get(),
                context.locale.get(),
            )
        }
    });
    reactive(
        source,
        move |scope, (contacts, agents, query, expanded, ..)| {
            let own_expanded = ui.own_agents_expanded;
            let query = query.trim().to_ascii_lowercase();
            let mut groups = Vec::new();
            let actor = super::principal_id_owned(context.principal_id.get());
            let own_label = if context.account_primary_handle.get().trim().is_empty() {
                context
                    .state_store
                    .read(|store| crate::views::helpers::actor_display_label(store, &actor))
            } else {
                context.account_primary_handle.get()
            };
            let show_own = !context.token.get().is_empty()
                && (sidebar_text_matches_query(&query, &[&actor, &own_label])
                    || agents.iter().any(|agent| {
                        sidebar_text_matches_query(
                            &query,
                            &[
                                agent.agent_id.as_str(),
                                agent.display_name.as_deref().unwrap_or_default(),
                                &agent.slug,
                            ],
                        )
                    }));
            let own_avatar = crate::components::generated_avatar::identity_avatar_inline(
                scope,
                context.clone(),
                crate::components::IdentityAvatarProps {
                    seed: actor.clone(),
                    alt_text: own_label.clone(),
                    blob_ref: Some(
                        context
                            .state_store
                            .read(|store| store.load_plain_local_data("avatar_blob_ref"))
                            .unwrap_or_else(|| ui.avatar.get()),
                    )
                    .filter(|value| !value.is_empty()),
                    class: "sidebar-nav-icon contact-sidebar-user-avatar avatar-img".into(),
                    test_id: None,
                },
            );
            let mut own = vec![Box::new(
                sapid::button()
                    .unstyled()
                    .class("sidebar-nav-item contact-sidebar-row contact-sidebar-user-row contact-sidebar-self-row")
                    .name(scope.bond({
                        let context = context.clone();
                        move || {
                            context.tr(if own_expanded.get() {
                                "app.sidebar.hide_own_agents"
                            } else {
                                "app.sidebar.show_own_agents"
                            })
                        }
                    }))
                    .fill(vec![
                        own_avatar,
                        Box::new(text().class("grow truncate").content(own_label)),
                        crate::components::self_attribution::self_attribution_badge_inline(
                            scope,
                            context.clone(),
                            crate::components::SelfAttributionBadgeProps {
                                test_id: Some("contact-sidebar-self-badge".into()),
                                ..Default::default()
                            },
                        ),
                        Box::new(
                            glory::ui::when(own_expanded, || {
                                crate::components::icons::ui_icon_with_class(
                                    "chevron-down",
                                    "ui-icon contact-agent-chevron contact-sidebar-self-agent-toggle",
                                )
                            })
                            .otherwise(|| {
                                crate::components::icons::ui_icon_with_class(
                                    "chevron-right",
                                    "ui-icon contact-agent-chevron",
                                )
                            }),
                        ),
                    ])
                    .on_press({
                        let expanded = ui.own_agents_expanded;
                        move || expanded.revise(|value| *value = !*value)
                    }),
            ) as View];
            own.push(reactive_distinct(own_expanded, {
                let context = context.clone();
                let ui = ui.clone();
                let agents = agents.clone();
                let query = query.clone();
                let actor = actor.clone();
                move |scope, expanded| {
                    if !expanded {
                        return empty();
                    }
                    let mut own_agents = Vec::new();
                    for agent in agents.iter().filter(|agent| {
                        sidebar_text_matches_query(
                            &query,
                            &[
                                agent.agent_id.as_str(),
                                agent.display_name.as_deref().unwrap_or_default(),
                                &agent.slug,
                            ],
                        )
                    }) {
                        let id = agent.agent_id.to_string();
                        let label = agent
                            .display_name
                            .clone()
                            .unwrap_or_else(|| agent.slug.clone());
                        own_agents.push(direct_button(
                            scope,
                            context.clone(),
                            ui.clone(),
                            label,
                            id.clone(),
                            agent.avatar_blob_ref.as_ref().map(ToString::to_string),
                            format!("owned-agent:{id}"),
                            super::direct_open::DirectConversationTarget::OwnedAgent {
                                agent_id: id,
                                controller_principal_id: actor.clone(),
                            },
                            None,
                            true,
                            "sidebar-nav-item contact-sidebar-agent-row",
                        ));
                    }
                    block("contact-agent-list contact-sidebar-self-agents", own_agents)
                }
            }));
            if show_own {
                groups.push(block(
                    "contact-sidebar-group is-self contact-sidebar-self-group",
                    own,
                ));
            }
            let contacts = context.state_store.read(|store| {
                super::shell_model::filter_and_sort_direct_contacts(
                    &contacts,
                    &query,
                    store,
                    &store.contact_remarks(),
                )
            });
            for contact in contacts {
                let peer = contact.peer.contact_actor_id().to_string();
                let principal = crate::models::contact_peer_id(&contact).to_string();
                let label = context
                    .state_store
                    .read(|store| crate::views::helpers::contact_peer_label(store, &contact));
                let can_resolve = contact.state == arkret_sdk::ContactState::Accepted
                    && (contact
                        .bidirectional_scopes
                        .iter()
                        .chain(contact.effective_scopes.iter().flatten())
                        .any(|scope| {
                            *scope == arkret_sdk::contact_operations::ContactScope::DirectMessage
                        })
                        || contact.direct_conversation.as_ref().is_some_and(|direct| {
                            direct.state == arkret_sdk::DirectConversationSummaryState::Found
                        }));
                let mut children = vec![direct_button(
                    scope,
                    context.clone(),
                    ui.clone(),
                    label.clone(),
                    peer.clone(),
                    None,
                    format!("contact:{peer}"),
                    super::direct_open::DirectConversationTarget::Peer {
                        peer_id: peer.clone(),
                    },
                    contact.direct_conversation.clone(),
                    can_resolve,
                    if can_resolve {
                        "sidebar-nav-item contact-sidebar-row sidebar-row-main direct-conversation-row"
                    } else {
                        "sidebar-nav-item contact-sidebar-row sidebar-row-main is-dim direct-conversation-row"
                    },
                )];
                let key = peer.clone();
                let selected = ui.expanded_contacts;
                if !contact.contact_agent_projections.is_empty() {
                    let count = contact.contact_agent_projections.len();
                    children.push(Box::new(
                        sapid::button()
                            .unstyled()
                            .class("pill muted xs contact-agent-count contact-sidebar-agent-toggle")
                            .label(crate::i18n::tr_args(
                                "app.sidebar.agent_count",
                                &[("count", count.to_string())],
                            ))
                            .on_press(move || {
                                selected.revise(|value| {
                                    if !value.remove(&key) {
                                        value.insert(key.clone());
                                    }
                                });
                            }),
                    ));
                }
                let source = ui.row_menu;
                let menu_key = format!("contact:{peer}");
                let menu_id = menu_key.clone();
                let contact_menu_button = icon_action(
                    "sidebar-row-menu-button",
                    "Contact actions",
                    "more-horizontal",
                    move || {
                        source.revise(|value| {
                            *value = if value.as_ref() == Some(&menu_id) {
                                None
                            } else {
                                Some(menu_id.clone())
                            }
                        })
                    },
                );
                let menu_context = context.clone();
                let menu_ui = ui.clone();
                let contact_label = label.clone();
                let contact_peer = peer.clone();
                let menu_contact = contact.clone();
                let contact_menu = reactive(ui.row_menu, move |scope, open| {
                    if open.as_deref() != Some(&menu_key) {
                        return empty();
                    }
                    let mut actions = Vec::new();
                    if menu_contact.state == arkret_sdk::ContactState::Accepted
                        && matches!(
                            &menu_contact.peer,
                            arkret_sdk::contact_operations::ContactPeer::Human { .. }
                        )
                    {
                        let context = menu_context.clone();
                        let id = principal.clone();
                        let existing = context.state_store.read(|store| store.contact_remark(&id));
                        let next = !existing.as_ref().is_some_and(|remark| remark.pinned);
                        actions.push(action(
                            "sidebar-row-menu-item",
                            context.translated(
                                scope,
                                if next { "contact.pin" } else { "contact.unpin" },
                            ),
                            move || {
                                toggle_sidebar_contact_pin(
                                    context.clone(),
                                    id.clone(),
                                    existing.clone(),
                                    next,
                                    context.state_store.clone(),
                                    context.base_url.get(),
                                    context.token.get(),
                                )
                            },
                        ));
                    }
                    let pending = menu_ui.pending_delete;
                    let peer = contact_peer.clone();
                    let label = contact_label.clone();
                    actions.push(action(
                        "sidebar-row-menu-item danger",
                        menu_context.translated(scope, "common.delete"),
                        move || {
                            pending.revise(|value| *value = Some((peer.clone(), label.clone())))
                        },
                    ));
                    block("sidebar-row-menu-panel", actions)
                });
                let row_menu = ui.row_menu;
                let host_key = format!("contact:{peer}");
                let host_class = scope.bond(move || {
                    if row_menu.get().as_deref() == Some(host_key.as_str()) {
                        "sidebar-row-menu-host is-open".to_owned()
                    } else {
                        "sidebar-row-menu-host".to_owned()
                    }
                });
                children.push(Box::new(
                    view()
                        .class(host_class)
                        .fill(vec![contact_menu_button, contact_menu]),
                ));
                let mut group = vec![block(
                    if contact.contact_agent_projections.is_empty() {
                        "sidebar-row contact-sidebar-action-row"
                    } else {
                        "sidebar-row contact-sidebar-action-row has-contact-agents"
                    },
                    children,
                )];
                if expanded.contains(&peer) || !query.is_empty() {
                    let controller = match &contact.peer {
                        arkret_sdk::contact_operations::ContactPeer::Human { account_id } => {
                            serde_json::to_string(account_id)
                        }
                        arkret_sdk::contact_operations::ContactPeer::Agent {
                            controller_account_id,
                            ..
                        } => serde_json::to_string(controller_account_id),
                    }
                    .unwrap_or_default();
                    let agents = contact
                        .contact_agent_projections
                        .iter()
                        .map(|agent| {
                            let id = agent.actor_id.to_string();
                            let label = agent
                                .display_name
                                .clone()
                                .or_else(|| agent.agent_slug.clone())
                                .unwrap_or_else(|| short_protocol_id(&id));
                            direct_button(
                                scope,
                                context.clone(),
                                ui.clone(),
                                label,
                                id.clone(),
                                agent.avatar_blob_ref.as_ref().map(ToString::to_string),
                                format!("contact-agent:{id}"),
                                super::direct_open::DirectConversationTarget::ContactAgent {
                                    agent_id: id,
                                    controller: controller.clone(),
                                },
                                agent.direct_conversation.clone(),
                                true,
                                "sidebar-nav-item contact-sidebar-agent-row",
                            )
                        })
                        .collect();
                    group.push(block(
                        "contact-agent-list contact-sidebar-contact-agents",
                        agents,
                    ));
                }
                groups.push(block("contact-sidebar-group", group));
            }
            block("contact-sidebar-list", groups)
        },
    )
}
