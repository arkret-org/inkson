//! The Direct Conversation index uses the same peer bindings and open flow as Contacts.
use super::*;
use crate::app::direct_open::DirectConversationTarget;
use crate::models::{ContactView, DirectConversationSummary};
use crate::presentation::widgets::Resource;
use arkret_sdk::contact_operations::ContactPeer;

pub(super) fn summary_route(summary: Option<&DirectConversationSummary>) -> Option<Route> {
    let summary =
        summary.filter(|s| s.state == arkret_sdk::DirectConversationSummaryState::Found)?;
    Some(Route::DirectConversation {
        realm_id: summary.realm_id.to_string(),
        strand_id: summary.main_strand_id.to_string(),
    })
}

#[derive(Clone, PartialEq)]
struct ChatRow {
    realm: String,
    peer: ContactPeer,
    title: String,
    avatar: Option<String>,
    destination: Option<Route>,
    available: bool,
}

async fn resolve_owned_chat(
    http: &arkret_sdk::http_client::Client,
    agent: arkret_sdk::AgentProjection,
    controller: &arkret_sdk::AccountId,
) -> Option<ChatRow> {
    let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        agent.agent_id,
        controller.station_id.clone(),
    ));
    let peer = ContactPeer::Agent {
        actor_id,
        controller_account_id: controller.clone(),
    };
    let request = arkret_sdk::direct_conversation::DirectConversationResolveRequestBody {
        peer: peer.clone(),
    };
    let outcome = http.direct_conversation_resolve(&request).await.ok()?;
    let coordinates = outcome.coordinates()?;
    let realm = coordinates.realm_id.to_string();
    let available = !matches!(
        outcome,
        arkret_sdk::DirectConversationResolveResponseBody::Suspended { .. }
    );
    Some(ChatRow {
        destination: available.then(|| Route::DirectConversation {
            realm_id: realm.clone(),
            strand_id: coordinates.main_strand_id.to_string(),
        }),
        realm,
        peer,
        available,
        title: agent.display_name.unwrap_or(agent.slug),
        avatar: agent.avatar_blob_ref.map(|blob| blob.to_string()),
    })
}

// Owned Agent projections have no DM summary. Resolve their exact pairs on
// entry; the read endpoint never founds a Realm or sends a message.
fn owned_chats(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<ShellState>,
) -> Resource<Vec<ChatRow>> {
    resource(scope, move || {
        let account = context.active_account.get();
        let generation = context.session_generation.get();
        let contacts_ready = ui.contacts_loaded.get();
        let agents = ui.agents.get();
        let base = context.base_url.get();
        let token = context.token.get();
        let context = context.clone();
        async move {
            if !contacts_ready || token.is_empty() || agents.is_empty() {
                return Ok(Vec::new());
            }
            let Some(session) = account.as_ref() else {
                return Ok(Vec::new());
            };
            let controller = session.authority.clone();
            let rows =
                crate::transport::auth::with_authed_sdk_client(&base, token, |http| async move {
                    use futures_util::{StreamExt, stream};
                    let rows = stream::iter(agents)
                        .map(|agent| resolve_owned_chat(&http, agent, &controller))
                        .buffer_unordered(4)
                        .filter_map(std::future::ready)
                        .collect::<Vec<_>>()
                        .await;
                    Ok(rows)
                })
                .await
                .map_err(|error| error.display_diagnostic())?;
            if !context.session_matches(generation, &account) {
                return Ok(Vec::new());
            }
            context
                .state_store
                .write(|store| {
                    for row in &rows {
                        store.save_direct_conversation_peer(row.realm.clone(), row.peer.clone())?;
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .map_err(|error| error.to_string())?;
            Ok(rows)
        }
    })
}

fn chat_rows(
    store: &crate::state::LocalStateStore,
    account: &arkret_sdk::AccountId,
    contacts: &[ContactView],
    owned: Vec<ChatRow>,
) -> Vec<ChatRow> {
    let state = store.load();
    let remembered: BTreeMap<_, _> = state
        .direct_conversation_peers
        .iter()
        .map(|(realm, peer)| (peer.contact_actor_id().to_string(), (realm, peer)))
        .collect();
    let mut rows = BTreeMap::new();
    let mut add =
        |peer: ContactPeer, title: String, avatar, summary: Option<&DirectConversationSummary>| {
            let remembered_realm = remembered
                .get(&peer.contact_actor_id().to_string())
                .filter(|(_, saved)| **saved == peer)
                .map(|(realm, _)| realm.as_str());
            let Some(realm) = summary.map(|s| s.realm_id.as_str()).or(remembered_realm) else {
                return;
            };
            let available = summary
                .is_none_or(|s| s.state == arkret_sdk::DirectConversationSummaryState::Found);
            let destination = if summary.is_some() {
                summary_route(summary)
            } else {
                store
                    .direct_message_context(realm, &arkret_sdk::ActorId::account(account.clone()))
                    .map(|binding| Route::DirectConversation {
                        realm_id: realm.to_owned(),
                        strand_id: binding.main_strand_id.to_string(),
                    })
            };
            if summary.is_none() && destination.is_none() {
                return;
            }
            rows.entry(realm.to_owned()).or_insert_with(|| ChatRow {
                realm: realm.to_owned(),
                peer,
                title,
                avatar,
                destination,
                available,
            });
        };
    for contact in contacts
        .iter()
        .filter(|c| c.state == arkret_sdk::ContactState::Accepted)
    {
        add(
            contact.peer.clone(),
            crate::views::helpers::contact_peer_label(store, contact),
            None,
            contact.direct_conversation.as_ref(),
        );
        for agent in &contact.contact_agent_projections {
            add(
                ContactPeer::Agent {
                    actor_id: agent.actor_id.clone(),
                    controller_account_id: agent.controller_account_id.clone(),
                },
                agent
                    .display_name
                    .clone()
                    .or_else(|| agent.agent_slug.clone())
                    .unwrap_or_else(|| short_protocol_id(&agent.actor_id.to_string())),
                agent.avatar_blob_ref.as_ref().map(ToString::to_string),
                agent.direct_conversation.as_ref(),
            );
        }
    }
    for row in owned {
        rows.insert(row.realm.clone(), row);
    }
    let mut rows: Vec<_> = rows.into_values().collect();
    rows.sort_by_cached_key(|row| (row.title.to_lowercase(), row.realm.clone()));
    rows
}

pub(super) fn list(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<ShellState>,
    search: Cage<String>,
) -> View {
    let owned = owned_chats(scope, context.clone(), ui.clone()).data;
    let index = scope.bond({
        let context = context.clone();
        move || {
            let _ = context.state_revision.get();
            let _ = context.locale.get();
            let Some(account) = context.active_account.get() else {
                return Vec::new();
            };
            let contacts = context.contact_rows.get();
            let agents = owned.get().and_then(|result| result.ok()).unwrap_or_default();
            context
                .state_store
                .read(|store| chat_rows(store, &account.authority, &contacts, agents))
        }
    });
    scope.effect({
        let context = context.clone();
        let contacts_ready = ui.contacts_loaded;
        move || {
            if context.route.get() != Route::PrivateChats
                || context.workspace_navigation.layout.mobile().get()
                || !contacts_ready.get()
            {
                return;
            }
            let rows = index.get();
            let previous = context.selected_realm_id.get_untracked();
            let destination = rows
                .iter()
                .find(|row| row.realm == previous)
                .and_then(|row| row.destination.clone())
                .or_else(|| rows.iter().find_map(|row| row.destination.clone()));
            if let Some(route) = destination {
                context.replace_route(route);
            }
        }
    });
    let route = context.route;
    let source = scope.bond(move || (index.get(), route.get(), search.get()));
    reactive_distinct(source, move |scope, (rows, current, query)| {
        let query = query.trim().to_lowercase();
        let mut items = Vec::new();
        for row in rows {
            let id = row.peer.contact_actor_id().to_string();
            if !sidebar_text_matches_query(&query, &[&row.title, &id]) {
                continue;
            }
            let target = match &row.peer {
                ContactPeer::Human { .. } => DirectConversationTarget::Peer {
                    peer_id: id.clone(),
                },
                ContactPeer::Agent {
                    controller_account_id,
                    ..
                } => DirectConversationTarget::ContactAgent {
                    agent_id: id.clone(),
                    controller: controller_account_id.to_string(),
                },
            };
            let active = current.realm_id() == Some(row.realm.as_str());
            let class = if active {
                "sidebar-nav-item contact-sidebar-row direct-conversation-row private-chat-row is-active"
            } else {
                "sidebar-nav-item contact-sidebar-row direct-conversation-row private-chat-row"
            };
            items.push(direct_button(
                scope,
                context.clone(),
                ui.clone(),
                row.title,
                id,
                row.avatar,
                format!("private-chat:{}", row.realm),
                target,
                row.destination,
                row.available,
                class,
            ));
        }
        if items.is_empty() {
            items.push(paragraph(
                "muted private-chats-empty",
                context.translated(
                    scope,
                    if query.is_empty() {
                        "direct.empty_chats"
                    } else {
                        "direct.no_matches"
                    },
                ),
            ));
        }
        block("contact-sidebar-list private-chat-list", items)
    })
}
