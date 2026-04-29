use dioxus::prelude::*;
use serde_json::Value;

use crate::{models::*, views::helpers::authed_api};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryTab {
    Spaces,
    Organizations,
    Actors,
    Handles,
    Applets,
}

#[derive(Clone, Debug, Default)]
struct PaginationState {
    spaces_cursor: Option<String>,
    orgs_cursor: Option<String>,
    actors_cursor: Option<String>,
    index_cursor: Option<String>,
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
    let mut index_results = use_signal(Vec::<Value>::new);
    let mut handle_result = use_signal(|| Option::<ResolveHandleResponse>::None);
    let mut contact_status = use_signal(|| String::new());
    let mut pagination = use_signal(PaginationState::default);
    let mut applet_results = use_signal(Vec::<Value>::new);
    let mut applet_status = use_signal(|| String::new());
    let base_url_key = base_url.clone();

    rsx! {
        div { class: "timeline", "data-testid": "directory-panel", role: "region", "aria-label": "Directory search",
            // Tab bar
            div { class: "actions", "data-testid": "directory-tabs", role: "tablist", "aria-label": "Directory categories",
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
                button {
                    class: if active_tab() == DirectoryTab::Applets { "primary" } else { "secondary" },
                    "data-testid": "tab-applets",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Applets { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Applets),
                    "Applets"
                }
            }

            // Search input
            div { class: "event",
                div { class: "event-head",
                    span { "Directory" }
                    span { match active_tab() {
                        DirectoryTab::Spaces => "search and resolve spaces",
                        DirectoryTab::Organizations => "search organizations",
                        DirectoryTab::Actors => "search actors",
                        DirectoryTab::Handles => "resolve handle",
                        DirectoryTab::Applets => "discover applets",
                    }}
                }
                div { class: "search",
                    input {
                        "data-testid": "directory-search-input",
                        value: "{query}",
                        "aria-label": match active_tab() {
                            DirectoryTab::Spaces => "Search spaces",
                            DirectoryTab::Organizations => "Search organizations",
                            DirectoryTab::Actors => "Search actors",
                            DirectoryTab::Handles => "Resolve handle",
                            DirectoryTab::Applets => "Discover applets",
                        },
                        placeholder: match active_tab() {
                            DirectoryTab::Spaces => "Search spaces",
                            DirectoryTab::Organizations => "Search organizations",
                            DirectoryTab::Actors => "Search actors",
                            DirectoryTab::Handles => "Enter handle (e.g. alice.example)",
                            DirectoryTab::Applets => "Enter applet DID",
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
                                pagination.write().index_cursor = None;
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match tab {
                                            DirectoryTab::Spaces => {
                                                match api.search_spaces(&q, None).await {
                                                    Ok(search) => {
                                                        pagination.write().spaces_cursor = search.next_cursor.clone();
                                                        let results = search.results;
                                                        let space_ids = results
                                                            .iter()
                                                            .map(|space| space.space_id.clone())
                                                            .collect::<Vec<_>>();
                                                        spaces.set(results);
                                                        if space_ids.is_empty() {
                                                            index_results.set(Vec::new());
                                                        } else {
                                                            match api.index_query(&space_ids, None).await {
                                                                Ok(index) => {
                                                                    pagination.write().index_cursor = index.next_cursor.clone();
                                                                    status.set(format!(
                                                                        "indexed {} space projection(s)",
                                                                        index.results.len()
                                                                    ));
                                                                    index_results.set(index.results);
                                                                }
                                                                Err(error) => {
                                                                    index_results.set(Vec::new());
                                                                    status.set(format!("index query failed: {error}"));
                                                                }
                                                            }
                                                        }
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
                                            DirectoryTab::Applets => {
                                                match api.applet_describe(&q).await {
                                                    Ok(applet) => {
                                                        let value = serde_json::to_value(&applet).unwrap_or_default();
                                                        applet_results.set(vec![value]);
                                                        applet_status.set(format!("found applet {}", applet.name));
                                                    }
                                                    Err(error) => {
                                                        applet_results.set(Vec::new());
                                                        applet_status.set(format!("applet lookup failed: {error}"));
                                                    }
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
                                    pagination.write().index_cursor = None;
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match tab {
                                                DirectoryTab::Spaces => {
                                                    match api.search_spaces(&q, None).await {
                                                        Ok(search) => {
                                                            pagination.write().spaces_cursor = search.next_cursor.clone();
                                                            let results = search.results;
                                                            let space_ids = results
                                                                .iter()
                                                                .map(|space| space.space_id.clone())
                                                                .collect::<Vec<_>>();
                                                            spaces.set(results);
                                                            if space_ids.is_empty() {
                                                                index_results.set(Vec::new());
                                                            } else {
                                                                match api.index_query(&space_ids, None).await {
                                                                    Ok(index) => {
                                                                        pagination.write().index_cursor = index.next_cursor.clone();
                                                                        status.set(format!(
                                                                            "indexed {} space projection(s)",
                                                                            index.results.len()
                                                                        ));
                                                                        index_results.set(index.results);
                                                                    }
                                                                    Err(error) => {
                                                                        index_results.set(Vec::new());
                                                                        status.set(format!("index query failed: {error}"));
                                                                    }
                                                                }
                                                            }
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
                                                DirectoryTab::Applets => {
                                                    match api.applet_describe(&q).await {
                                                        Ok(applet) => {
                                                            let value = serde_json::to_value(&applet).unwrap_or_default();
                                                            applet_results.set(vec![value]);
                                                            applet_status.set(format!("found applet {}", applet.name));
                                                        }
                                                        Err(error) => {
                                                            applet_results.set(Vec::new());
                                                            applet_status.set(format!("applet lookup failed: {error}"));
                                                        }
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
                            button {
                                class: "primary",
                                "data-testid": "open-space-button",
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
                            button {
                                class: "secondary",
                                "data-testid": "directory-contact-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let target = space.space_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let target = target.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.request_contact(&target).await {
                                                    Ok(c) => contact_status.set(format!("sent to {} ({})", c.target, c.status)),
                                                    Err(e) => contact_status.set(format!("contact failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Add Contact"
                            }
                        }
                    }
                }
                if !index_results().is_empty() {
                    div { class: "event", "data-testid": "index-query-results",
                        div { class: "event-head",
                            span { "Indexed Views" }
                            span { "{index_results().len()} result(s)" }
                        }
                        for result in index_results() {
                            div { class: "metric", "data-testid": "index-result",
                                strong { "{value_str(&result, \"kind\", \"view\")}" }
                                span { "{value_str(&result, \"title\", value_str(&result, \"space_id\", \"untitled\"))}" }
                            }
                        }
                    }
                }
                if pagination().spaces_cursor.is_some() || pagination().index_cursor.is_some() {
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
                            if pagination().index_cursor.is_some() {
                                button {
                                    class: "secondary",
                                    "data-testid": "load-more-index",
                                    disabled: pagination().loading_more,
                                    onclick: {
                                        let base = base_url.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let space_ids = spaces().iter().map(|s| s.space_id.clone()).collect::<Vec<_>>();
                                            let api_token = token();
                                            let cursor = pagination.read().index_cursor.clone();
                                            pagination.write().loading_more = true;
                                            spawn(async move {
                                                if let Ok(api) = authed_api(&base, api_token) {
                                                    match api.index_query(&space_ids, cursor.as_deref()).await {
                                                        Ok(index) => {
                                                            pagination.write().index_cursor = index.next_cursor.clone();
                                                            let mut current = index_results();
                                                            current.extend(index.results);
                                                            index_results.set(current);
                                                        }
                                                        Err(error) => status.set(format!("load more index failed: {error}")),
                                                    }
                                                }
                                                pagination.write().loading_more = false;
                                            });
                                        }
                                    },
                                    if pagination().loading_more { "Loading..." } else { "Load More Index" }
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
                    div { class: "event",
                        div { class: "event-head", span { "Organizations" } span { "empty" } }
                        div { class: "muted", "No organizations found. Try a search." }
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
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "actor-contact-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let target = actor.get("did").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                                    move |_| {
                                        let base = base.clone();
                                        let target = target.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.request_contact(&target).await {
                                                    Ok(c) => contact_status.set(format!("sent to {} ({})", c.target, c.status)),
                                                    Err(e) => contact_status.set(format!("contact failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Add Contact"
                            }
                        }
                    }
                }
                if actor_results().is_empty() {
                    div { class: "event",
                        div { class: "event-head", span { "Actors" } span { "empty" } }
                        div { class: "muted", "No actors found. Try a search." }
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

            // Applets tab results
            if active_tab() == DirectoryTab::Applets {
                if !applet_status().is_empty() {
                    div { class: "muted", "data-testid": "applet-status", "{applet_status}" }
                }
                for applet in applet_results() {
                    div { class: "event", "data-testid": "applet-result",
                        div { class: "event-head",
                            span { "applet" }
                            span { "{value_str(&applet, \"applet_did\", \"-\")}" }
                        }
                        div { class: "space-title", "{value_str(&applet, \"name\", \"unknown\")}" }
                        div { class: "muted", "Version: {value_str(&applet, \"version\", \"?\")}" }
                        {
                            let caps = value_vec(&applet, "capabilities");
                            if !caps.is_empty() {
                                rsx! {
                                    div { class: "muted", "Capabilities: {caps.join(\", \")}" }
                                }
                            } else {
                                rsx! { div {} }
                            }
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "applet-ping-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let did = value_str(&applet, "applet_did", "");
                                    move |_| {
                                        let base = base.clone();
                                        let did = did.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.applet_ping(&did).await {
                                                    Ok(ping) => applet_status.set(format!(
                                                        "ping ok, latency: {}ms",
                                                        ping.latency_ms.unwrap_or(0)
                                                    )),
                                                    Err(e) => applet_status.set(format!("ping failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Ping"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "applet-metadata-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let did = value_str(&applet, "applet_did", "");
                                    move |_| {
                                        let base = base.clone();
                                        let did = did.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.applet_protocol_metadata(&did).await {
                                                    Ok(meta) => applet_status.set(format!(
                                                        "protocol v{}, {} operations, {} schemas",
                                                        meta.protocol_version,
                                                        meta.supported_operations.len(),
                                                        meta.supported_schemas.len()
                                                    )),
                                                    Err(e) => applet_status.set(format!("metadata failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Metadata"
                            }
                        }
                    }
                }
                if applet_results().is_empty() && applet_status().is_empty() {
                    div { class: "event",
                        div { class: "event-head", span { "Applets" } span { "discovery" } }
                        div { class: "muted", "Enter an applet DID above and click Search to discover it." }
                    }
                }
            }

            if !contact_status().is_empty() {
                div { class: "muted", "data-testid": "contact-status", "{contact_status}" }
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
