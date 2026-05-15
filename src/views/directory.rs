use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::Value;

use crate::{
    components::{EmptyState, EmptyStateKind, HelpTip},
    models::*,
    routes::Route,
    views::helpers::{authed_api, with_authed_api},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryTab {
    ProtocolObjects,
    Spaces,
    Organizations,
    Actors,
    Handles,
}

#[derive(Clone, Debug, Default)]
struct PaginationState {
    spaces_cursor: Option<String>,
    orgs_cursor: Option<String>,
    actors_cursor: Option<String>,
    loading_more: bool,
}

#[component]
pub fn DirectoryPanel(
    base_url: String,
    selected_space: Signal<String>,
    spaces: Signal<Vec<SpacePreview>>,
    status: Signal<String>,
    token: Signal<String>,
    view: Signal<super::View>,
) -> Element {
    let mut active_tab = use_signal(|| DirectoryTab::Spaces);
    let mut query = use_signal(String::new);
    let mut org_results = use_signal(Vec::<Value>::new);
    let mut actor_results = use_signal(Vec::<Value>::new);
    let mut object_results = use_signal(Vec::<Value>::new);
    let mut handle_result = use_signal(|| Option::<ResolveHandleResponse>::None);
    let mut contact_target_did = use_signal(|| "did:web:bob.example".to_owned());
    let mut contact_requester_did = use_signal(|| "did:web:alice.example".to_owned());
    let mut contact_state = use_signal(|| "No contact operation yet".to_owned());
    let mut pagination = use_signal(PaginationState::default);
    let base_url_key = base_url.clone();

    rsx! {
        div { class: "timeline", "data-testid": "directory-panel", role: "region", "aria-label": "Search workspace",
            // Tab bar
            div { class: "actions", "data-testid": "directory-tabs", role: "tablist", "aria-label": "Directory categories",
                button {
                    class: if active_tab() == DirectoryTab::ProtocolObjects { "primary" } else { "secondary" },
                    "data-testid": "tab-objects",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::ProtocolObjects { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::ProtocolObjects),
                    "Protocol Objects"
                }
                button {
                    class: if active_tab() == DirectoryTab::Spaces { "primary" } else { "secondary" },
                    "data-testid": "tab-spaces",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Spaces { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Spaces),
                    "Spaces"
                }
                button {
                    class: if active_tab() == DirectoryTab::Organizations { "primary" } else { "secondary" },
                    "data-testid": "tab-organizations",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Organizations { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Organizations),
                    "Organizations"
                }
                button {
                    class: if active_tab() == DirectoryTab::Actors { "primary" } else { "secondary" },
                    "data-testid": "tab-actors",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Actors { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Actors),
                    "Actors"
                }
                button {
                    class: if active_tab() == DirectoryTab::Handles { "primary" } else { "secondary" },
                    "data-testid": "tab-handles",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Handles { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Handles),
                    "Handles"
                }
            }

            div { class: "event directory-axis-card", "data-testid": "directory-three-axes-banner",
                div { class: "event-head",
                    span { "Search Policy Axes" }
                    span { "independent decisions" }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Discoverability" }
                        span {
                            crate::components::PermissionPill {
                                prefix: "disc".to_owned(),
                                value: "listed".to_owned(),
                                kind: "discoverability".to_owned(),
                            }
                        }
                        div { class: "muted", "can this be listed?" }
                    }
                    div { class: "metric",
                        strong { "Join Rule" }
                        span {
                            crate::components::PermissionPill {
                                prefix: "join".to_owned(),
                                value: "invite_only".to_owned(),
                                kind: "join_rule".to_owned(),
                            }
                        }
                        div { class: "muted", "can this actor join?" }
                    }
                    div { class: "metric",
                        strong { "History Visibility" }
                        span {
                            crate::components::PermissionPill {
                                prefix: "hist".to_owned(),
                                value: "shared_history".to_owned(),
                                kind: "history".to_owned(),
                            }
                        }
                        div { class: "muted", "what history is readable?" }
                    }
                }
                div { class: "actions", "data-testid": "permission-pill-examples",
                    crate::components::PermissionPillRow {
                        discoverability: Some("public".to_owned()),
                        join_rule: Some("knock".to_owned()),
                        history_visibility: Some("world_readable".to_owned()),
                    }
                    span { class: "muted", "·" }
                    crate::components::PermissionPillRow {
                        discoverability: Some("invite_only".to_owned()),
                        join_rule: Some("restricted".to_owned()),
                        history_visibility: Some("invited".to_owned()),
                    }
                }
            }

            div { class: "event", "data-testid": "directory-surface-map",
                div { class: "event-head",
                    span { "Search scope" }
                    span { "entity discovery only" }
                }
                div { class: "muted",
                    "Search stays focused on spaces, organizations, actors, handles, and protocol-level lookups. The old directory shortcut has been folded into the global search entrypoint."
                }
                div { class: "actions",
                    button {
                        class: if active_tab() == DirectoryTab::ProtocolObjects { "primary" } else { "secondary" },
                        onclick: move |_| active_tab.set(DirectoryTab::ProtocolObjects),
                        "Developer Object Lookup"
                    }
                }
            }

            div { class: "event", "data-testid": "directory-contact-tools",
                div { class: "event-head",
                    span { "Relationship tools" }
                    span { "actors / handles context" }
                }
                div { class: "muted",
                    "Contact and actor relationship actions now live with directory lookups instead of the setup page. Search for a DID or handle here, then issue the relationship operation against that actor."
                }
                div { class: "workflow-form",
                    input {
                        "data-testid": "contact-target-did-input",
                        value: "{contact_target_did}",
                        placeholder: "Target DID",
                        oninput: move |event| contact_target_did.set(event.value())
                    }
                    input {
                        "data-testid": "contact-requester-did-input",
                        value: "{contact_requester_did}",
                        placeholder: "Requester DID",
                        oninput: move |event| contact_requester_did.set(event.value())
                    }
                    div { class: "muted", "{contact_state}" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "request-contact-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                let target = contact_target_did();
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.request_contact(&target).await
                                    })
                                    .await
                                    {
                                        Ok(contact) => contact_state.set(format!(
                                            "request {} -> {} {}",
                                            contact.requester, contact.target, contact.status
                                        )),
                                        Err(err) => contact_state
                                            .set(format!("request: {}", err.display())),
                                    }
                                });
                            }
                        },
                        "Request"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "accept-contact-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                let requester = contact_requester_did();
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.respond_contact(&requester, "accept").await
                                    })
                                    .await
                                    {
                                        Ok(contact) => contact_state.set(format!(
                                            "respond {} -> {} {}",
                                            contact.requester, contact.target, contact.status
                                        )),
                                        Err(err) => contact_state
                                            .set(format!("accept: {}", err.display())),
                                    }
                                });
                            }
                        },
                        "Accept"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "reject-contact-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                let requester = contact_requester_did();
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.respond_contact(&requester, "reject").await
                                    })
                                    .await
                                    {
                                        Ok(contact) => contact_state.set(format!(
                                            "respond {} -> {} {}",
                                            contact.requester, contact.target, contact.status
                                        )),
                                        Err(err) => contact_state
                                            .set(format!("reject: {}", err.display())),
                                    }
                                });
                            }
                        },
                        "Reject"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "list-contacts-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                spawn(async move {
                                    match authed_api(&base, api_token) {
                                        Ok(api) => match api.contacts().await {
                                            Ok(result) => {
                                                let summary = result
                                                    .contacts
                                                    .iter()
                                                    .map(|contact| format!("{} -> {} {}", contact.requester, contact.target, contact.status))
                                                    .collect::<Vec<_>>()
                                                    .join(", ");
                                                contact_state.set(format!("contacts {} {}", result.contacts.len(), summary));
                                            }
                                            Err(error) => contact_state.set(format!("list failed: {error}")),
                                        },
                                        Err(error) => contact_state.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        },
                        "List"
                    }
                }
            }

            div { class: "event directory-search-card",
                div { class: "event-head",
                    span { "Search" }
                    span { match active_tab() {
                        DirectoryTab::ProtocolObjects => "developer objects",
                        DirectoryTab::Spaces => "spaces",
                        DirectoryTab::Organizations => "organizations",
                        DirectoryTab::Actors => "actors",
                        DirectoryTab::Handles => "handles",
                    }}
                }
                div { class: "search",
                    input {
                        "data-testid": "directory-search-input",
                        value: "{query}",
                        "aria-label": match active_tab() {
                            DirectoryTab::ProtocolObjects => "Search protocol objects for developer diagnostics",
                            DirectoryTab::Spaces => "Search spaces",
                            DirectoryTab::Organizations => "Search organizations",
                            DirectoryTab::Actors => "Search actors",
                            DirectoryTab::Handles => "Resolve handle",
                        },
                        placeholder: match active_tab() {
                            DirectoryTab::ProtocolObjects => "Search Cards, Discussions, Actors, Spaces (diagnostic lookup)",
                            DirectoryTab::Spaces => "Search spaces",
                            DirectoryTab::Organizations => "Search organizations",
                            DirectoryTab::Actors => "Search actors",
                            DirectoryTab::Handles => "Enter handle (e.g. alice.example)",
                        },
                        oninput: move |event| query.set(event.value()),
                        onkeydown: move |event| {
                            if event.key().to_string() == "Enter" {
                                let base = base_url_key.clone();
                                let q = query();
                                let tab = active_tab();
                                let api_token = token();
                                pagination.write().spaces_cursor = None;
                                pagination.write().orgs_cursor = None;
                                pagination.write().actors_cursor = None;
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match tab {
                                            DirectoryTab::ProtocolObjects => {
                                                object_results.set(protocol_object_results(&q));
                                                status.set("loaded protocol object diagnostic results".to_owned());
                                            }
                                            DirectoryTab::Spaces => {
                                                match api.search_spaces(&q, None).await {
                                                    Ok(search) => {
                                                        pagination.write().spaces_cursor = search.next_cursor.clone();
                                                        let count = search.results.len();
                                                        spaces.set(search.results);
                                                        status.set(format!("loaded {count} space result(s)"));
                                                    }
                                                    Err(error) => status.set(format!("search failed: {error}")),
                                                }
                                            }
                                            DirectoryTab::Organizations => {
                                                match api.search_organizations(&q, None).await {
                                                    Ok(search) => {
                                                        pagination.write().orgs_cursor = search.next_cursor.clone();
                                                        org_results.set(search.results);
                                                    }
                                                    Err(error) => status.set(format!("org search failed: {error}")),
                                                }
                                            }
                                            DirectoryTab::Actors => {
                                                match api.search_actors(&q, None).await {
                                                    Ok(search) => {
                                                        pagination.write().actors_cursor = search.next_cursor.clone();
                                                        actor_results.set(search.results);
                                                    }
                                                    Err(error) => status.set(format!("actor search failed: {error}")),
                                                }
                                            }
                                            DirectoryTab::Handles => {
                                                match api.resolve_handle(&q).await {
                                                    Ok(resolved) => handle_result.set(Some(resolved)),
                                                    Err(error) => status.set(format!("resolve failed: {error}")),
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                        },
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "directory-search-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let base = base.clone();
                                    let q = query();
                                    let tab = active_tab();
                                    let api_token = token();
                                    pagination.write().spaces_cursor = None;
                                    pagination.write().orgs_cursor = None;
                                    pagination.write().actors_cursor = None;
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match tab {
                                                DirectoryTab::ProtocolObjects => {
                                                    object_results.set(protocol_object_results(&q));
                                                    status.set("loaded protocol object diagnostic results".to_owned());
                                                }
                                                DirectoryTab::Spaces => {
                                                    match api.search_spaces(&q, None).await {
                                                        Ok(search) => {
                                                            pagination.write().spaces_cursor = search.next_cursor.clone();
                                                            let count = search.results.len();
                                                            spaces.set(search.results);
                                                            status.set(format!("loaded {count} space result(s)"));
                                                        }
                                                        Err(error) => status.set(format!("search failed: {error}")),
                                                    }
                                                }
                                                DirectoryTab::Organizations => {
                                                    match api.search_organizations(&q, None).await {
                                                        Ok(search) => {
                                                            pagination.write().orgs_cursor = search.next_cursor.clone();
                                                            org_results.set(search.results);
                                                        }
                                                        Err(error) => status.set(format!("org search failed: {error}")),
                                                    }
                                                }
                                                DirectoryTab::Actors => {
                                                    match api.search_actors(&q, None).await {
                                                        Ok(search) => {
                                                            pagination.write().actors_cursor = search.next_cursor.clone();
                                                            actor_results.set(search.results);
                                                        }
                                                        Err(error) => status.set(format!("actor search failed: {error}")),
                                                    }
                                                }
                                                DirectoryTab::Handles => {
                                                    match api.resolve_handle(&q).await {
                                                        Ok(resolved) => handle_result.set(Some(resolved)),
                                                        Err(error) => status.set(format!("resolve failed: {error}")),
                                                    }
                                                }
                                            }
                                        }
                                    });
                                }
                            },
                            "Search"
                        }
                        if active_tab() == DirectoryTab::Spaces {
                            button {
                                class: "secondary",
                                "data-testid": "resolve-selected-button",
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let id = selected_space();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.resolve_space(&id).await {
                                                    Ok(resolved) => {
                                                        selected_space.set(resolved.space_preview.space_id);
                                                        status.set(format!("resolved {}", resolved.join_rule));
                                                    }
                                                    Err(error) => status.set(format!("resolve failed: {error}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Resolve Selected"
                            }
                        }
                    }
                }
            }

            if active_tab() == DirectoryTab::ProtocolObjects {
                div { class: "event", "data-testid": "protocol-objects-banner",
                    div { class: "event-head",
                        span { "Developer object lookup" }
                        span { "diagnostic projection" }
                        HelpTip { text: "These results are for protocol debugging and model inspection. They are not the normal end-user directory surface." }
                    }
                }
                div { class: "event", "data-testid": "protocol-object-results",
                    div { class: "event-head", span { "Protocol Objects" } span { "{object_results().len()} result(s)" } }
                    if object_results().is_empty() {
                        div { class: "muted", "Search to see Card, Discussion, Actor and Space projections with visibility state." }
                    }
                    for result in object_results() {
                        ProtocolObjectResult { result }
                    }
                }
            }

            // Spaces tab results
            if active_tab() == DirectoryTab::Spaces {
                for space in spaces() {
                    div { class: "event", "data-testid": "directory-result",
                        div { class: "event-head",
                            span { "{space.category.clone().unwrap_or_else(|| \"space\".to_owned())}" }
                            span { if space.public { "public" } else { "private" } }
                        }
                        div { class: "space-title", "{space.name}" }
                        div { class: "muted", "{space.description.clone().unwrap_or_default()}" }
                        div { class: "actions",
                            Link {
                                class: "primary",
                                "data-testid": "open-space-button",
                                to: Route::Space { space_id: space.space_id.clone() },
                                onclick: {
                                    let id = space.space_id.clone();
                                    move |_| {
                                        selected_space.set(id.clone());
                                        view.set(super::View::Timeline);
                                    }
                                },
                                "Open Space"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "directory-select-button",
                                onclick: {
                                    let id = space.space_id.clone();
                                    move |_| selected_space.set(id.clone())
                                },
                                "Select"
                            }
                        }
                    }
                }
                if !spaces().is_empty() {
                    div { class: "event", "data-testid": "index-query-results",
                        div { class: "event-head", span { "Index Projection" } span { "{spaces().len()} result(s)" } }
                        for space in spaces() {
                            GenericEntityCard {
                                title: space.name.clone(),
                                summary: space.description.clone().unwrap_or_else(|| "Space projection".to_owned()),
                                entity_type: "space".to_owned(),
                            }
                        }
                    }
                }
                if pagination().spaces_cursor.is_some() {
                    div { class: "event",
                        div { class: "actions",
                            if pagination().spaces_cursor.is_some() {
                                button {
                                    class: "secondary",
                                    "data-testid": "load-more-spaces",
                                    disabled: pagination().loading_more,
                                    onclick: {
                                        let base = base_url.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let q = query();
                                            let api_token = token();
                                            let cursor = pagination.read().spaces_cursor.clone();
                                            pagination.write().loading_more = true;
                                            spawn(async move {
                                                if let Ok(api) = authed_api(&base, api_token) {
                                                    match api.search_spaces(&q, cursor.as_deref()).await {
                                                        Ok(search) => {
                                                            pagination.write().spaces_cursor = search.next_cursor.clone();
                                                            let mut current = spaces();
                                                            current.extend(search.results);
                                                            spaces.set(current);
                                                        }
                                                        Err(error) => status.set(format!("load more failed: {error}")),
                                                    }
                                                }
                                                pagination.write().loading_more = false;
                                            });
                                        }
                                    },
                                    if pagination().loading_more { "Loading..." } else { "Load More Spaces" }
                                }
                            }
                        }
                    }
                }
            }

            // Organizations tab results
            if active_tab() == DirectoryTab::Organizations {
                for org in org_results() {
                    {
                        let org_id = value_str(&org, "id", "-");
                        let org_did = value_str(&org, "did", org_id.as_str());
                        let org_name = value_str(&org, "name", "unknown");
                        let org_description = value_str(&org, "description", "");
                        let org_handle = value_str(&org, "handle", "");
                        let discoverability = value_str(&org, "discoverability", "unknown");
                        let profile_visibility = value_str(&org, "profile_visibility", "unknown");
                        let directory_services = value_vec(&org, "directory_services");
                        let proof_count = value_vec(&org, "proofs").len();
                        let actor_lookup_seed = if !org_handle.is_empty() {
                            org_handle.clone()
                        } else {
                            org_name.clone()
                        };
                        rsx! {
                            div { class: "event", "data-testid": "org-result",
                                div { class: "event-head",
                                    span { "organization" }
                                    span { "{org_did}" }
                                }
                                div { class: "space-title", "{org_name}" }
                                if !org_handle.is_empty() {
                                    div { class: "muted", "Handle: {org_handle}" }
                                }
                                div { class: "muted", "{org_description}" }
                                div { class: "actions",
                                    span { class: "badge badge-info", "Discoverability: {discoverability}" }
                                    span { class: "badge badge-info", "Profile: {profile_visibility}" }
                                    span { class: "badge badge-success", "{directory_services.len()} directory service(s)" }
                                    span { class: "badge badge-warning", "{proof_count} proof(s)" }
                                }
                                if !directory_services.is_empty() {
                                    div { class: "muted", "Directory services: {directory_services.join(\", \")}" }
                                }
                                div { class: "actions",
                                    button {
                                        class: "secondary",
                                        "data-testid": "org-search-members",
                                        onclick: {
                                            let seed = actor_lookup_seed.clone();
                                            move |_| {
                                                query.set(seed.clone());
                                                active_tab.set(DirectoryTab::Actors);
                                            }
                                        },
                                        "Search Members"
                                    }
                                    if !org_handle.is_empty() {
                                        button {
                                            class: "secondary",
                                            "data-testid": "org-resolve-handle",
                                            onclick: {
                                                let handle = org_handle.clone();
                                                move |_| {
                                                    query.set(handle.clone());
                                                    active_tab.set(DirectoryTab::Handles);
                                                }
                                            },
                                            "Resolve Handle"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if org_results().is_empty() {
                    EmptyState {
                        title: crate::i18n::tr("directory.tab.organizations"),
                        kind: EmptyStateKind::Empty,
                        message: Some(crate::i18n::tr("directory.org_empty_body")),
                        test_id: Some("directory-organizations-empty".to_owned()),
                    }
                }
                if pagination().orgs_cursor.is_some() {
                    div { class: "event",
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "load-more-orgs",
                                disabled: pagination().loading_more,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let q = query();
                                        let api_token = token();
                                        let cursor = pagination.read().orgs_cursor.clone();
                                        pagination.write().loading_more = true;
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.search_organizations(&q, cursor.as_deref()).await {
                                                    Ok(search) => {
                                                        pagination.write().orgs_cursor = search.next_cursor.clone();
                                                        let mut current = org_results();
                                                        current.extend(search.results);
                                                        org_results.set(current);
                                                    }
                                                    Err(error) => status.set(format!("load more failed: {error}")),
                                                }
                                            }
                                            pagination.write().loading_more = false;
                                        });
                                    }
                                },
                                if pagination().loading_more { "Loading..." } else { "Load More Organizations" }
                            }
                        }
                    }
                }
            }

            // Actors tab results
            if active_tab() == DirectoryTab::Actors {
                for actor in actor_results() {
                    div { class: "event", "data-testid": "actor-result",
                        div { class: "event-head",
                            span { "actor" }
                            span { "{actor.get(\"did\").and_then(|v| v.as_str()).unwrap_or(\"-\")}" }
                        }
                        div { class: "space-title", "{actor.get(\"handle\").and_then(|v| v.as_str()).unwrap_or(\"unknown\")}" }
                        div { class: "muted", "{actor.get(\"display_name\").and_then(|v| v.as_str()).unwrap_or(\"\")}" }
                    }
                }
                if actor_results().is_empty() {
                    EmptyState {
                        title: crate::i18n::tr("directory.tab.actors"),
                        kind: EmptyStateKind::Empty,
                        message: Some(crate::i18n::tr("directory.actors_empty_body")),
                        test_id: Some("directory-actors-empty".to_owned()),
                    }
                }
                if pagination().actors_cursor.is_some() {
                    div { class: "event",
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "load-more-actors",
                                disabled: pagination().loading_more,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let q = query();
                                        let api_token = token();
                                        let cursor = pagination.read().actors_cursor.clone();
                                        pagination.write().loading_more = true;
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.search_actors(&q, cursor.as_deref()).await {
                                                    Ok(search) => {
                                                        pagination.write().actors_cursor = search.next_cursor.clone();
                                                        let mut current = actor_results();
                                                        current.extend(search.results);
                                                        actor_results.set(current);
                                                    }
                                                    Err(error) => status.set(format!("load more failed: {error}")),
                                                }
                                            }
                                            pagination.write().loading_more = false;
                                        });
                                    }
                                },
                                if pagination().loading_more { "Loading..." } else { "Load More Actors" }
                            }
                        }
                    }
                }
            }

            // Handles tab result
            if active_tab() == DirectoryTab::Handles {
                if let Some(ref resolved) = handle_result() {
                    div { class: "event", "data-testid": "handle-result",
                        div { class: "event-head",
                            span { "Resolved" }
                            span { "{resolved.handle}" }
                        }
                        div { class: "space-title", "{resolved.did}" }
                        if let Some(ref doc) = resolved.did_document {
                            div { class: "muted", "DID document loaded" }
                            div { class: "muted", "{doc}" }
                        }
                    }
                } else {
                    div { class: "event",
                        div { class: "event-head", span { "Handles" } span { "lookup" } }
                        div { class: "muted", "Enter a handle above and click Search to resolve it." }
                    }
                }
            }

        }
    }
}

fn value_str(value: &Value, key: &str, fallback: impl Into<String>) -> String {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| fallback.into())
}

fn json_text(value: &Value, key: &str) -> String {
    value_str(value, key, "-")
}

#[component]
fn GenericEntityCard(title: String, summary: String, entity_type: String) -> Element {
    rsx! {
        div {
            class: "event nested-card",
            "data-testid": "generic-entity-card",
            "data-render-kind": "card",
            div { class: "event-head",
                span { "data-testid": "entity-type-label", "{entity_type}" }
                span { "projection" }
            }
            div { class: "space-title", "{title}" }
            div { class: "muted", "{summary}" }
            div { class: "actions",
                span { class: "badge green", "data-testid": "entity-facets", "renderable" }
                span { class: "badge blue", "data-testid": "projection-facets", "item: stateful, rankable" }
                span { class: "badge amber", "data-testid": "unknown-facets-debug", "com.example.preview" }
            }
        }
    }
}

#[component]
fn ProtocolObjectResult(result: Value) -> Element {
    let kind = json_text(&result, "kind");
    let access = json_text(&result, "access");
    let title = json_text(&result, "title");
    let summary = json_text(&result, "summary");
    let renderer = json_text(&result, "renderer");
    let facets = json_value(&result, &["facets"]);
    let discoverable = json_text(&result, "discoverable");

    rsx! {
        div { class: "event", "data-testid": "protocol-object-result",
            div { class: "event-head",
                span { "{kind}" }
                span { class: object_state_class(access.as_str()), "{access}" }
            }
            div { class: "space-title", "{title}" }
            div { class: "muted", "{summary}" }
            div { class: "actions",
                span { class: "badge", "renderer {renderer}" }
                span { class: "badge blue", "facets {facets}" }
                span { class: object_state_class(discoverable.as_str()), "discoverable {discoverable}" }
                if access.as_str() == "locked" || access.as_str() == "external" {
                    crate::components::LazyLinkBadge {
                        target_ref: None,
                        reason: Some(access.clone()),
                    }
                }
            }
        }
    }
}

fn json_value(value: &Value, path: &[&str]) -> String {
    let mut current = value;
    for key in path {
        let Some(next) = current.get(*key) else {
            return "-".to_owned();
        };
        current = next;
    }
    if let Some(text) = current.as_str() {
        text.to_owned()
    } else if current.is_null() {
        "-".to_owned()
    } else {
        current.to_string()
    }
}

fn object_state_class(state: &str) -> &'static str {
    match state {
        "readable" | "true" => "badge green",
        "discoverable" | "external" => "badge blue",
        "locked" | "false" => "badge amber",
        _ => "badge",
    }
}

fn protocol_object_results(query: &str) -> Vec<Value> {
    let query = query.trim();
    let suffix = if query.is_empty() { "all" } else { query };
    vec![
        serde_json::json!({
            "kind": "Card",
            "title": format!("Launch checklist card ({suffix})"),
            "summary": "Board Card projection with primary Discussion and independent ACL.",
            "renderer": "card",
            "facets": ["renderable", "stateful", "rankable"],
            "access": "readable",
            "discoverable": "true"
        }),
        serde_json::json!({
            "kind": "Discussion",
            "title": "Support desk discussion",
            "summary": "Discussion projection with history_visibility=shared and linked flow metadata.",
            "renderer": "thread",
            "facets": ["renderable", "messageable"],
            "access": "readable",
            "discoverable": "true"
        }),
        serde_json::json!({
            "kind": "Discussion",
            "title": "Restricted discussion",
            "summary": "Locked lazy link: existence can be hinted only by opaque policy-safe reference.",
            "renderer": "locked",
            "facets": ["renderable"],
            "access": "locked",
            "discoverable": "false"
        }),
        serde_json::json!({
            "kind": "Actor",
            "title": "did:web:alice.example",
            "summary": "Verified handle, claim badge, pairwise DID available for private contact.",
            "renderer": "row",
            "facets": ["renderable", "claimable"],
            "access": "discoverable",
            "discoverable": "true"
        }),
    ]
}

fn value_vec(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
