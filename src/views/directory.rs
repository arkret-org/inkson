use dioxus::prelude::*;
use serde_json::Value;

use crate::{
    api::ContrixApi,
    models::*,
    views::helpers::authed_api,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryTab {
    Spaces,
    Organizations,
    Actors,
    Handles,
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
    let mut handle_result = use_signal(|| Option::<ResolveHandleResponse>::None);
    let mut contact_status = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "directory-panel",
            // Tab bar
            div { class: "actions", "data-testid": "directory-tabs",
                button {
                    class: if active_tab() == DirectoryTab::Spaces { "primary" } else { "secondary" },
                    "data-testid": "tab-spaces",
                    onclick: move |_| active_tab.set(DirectoryTab::Spaces),
                    "Spaces"
                }
                button {
                    class: if active_tab() == DirectoryTab::Organizations { "primary" } else { "secondary" },
                    "data-testid": "tab-organizations",
                    onclick: move |_| active_tab.set(DirectoryTab::Organizations),
                    "Organizations"
                }
                button {
                    class: if active_tab() == DirectoryTab::Actors { "primary" } else { "secondary" },
                    "data-testid": "tab-actors",
                    onclick: move |_| active_tab.set(DirectoryTab::Actors),
                    "Actors"
                }
                button {
                    class: if active_tab() == DirectoryTab::Handles { "primary" } else { "secondary" },
                    "data-testid": "tab-handles",
                    onclick: move |_| active_tab.set(DirectoryTab::Handles),
                    "Handles"
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
                    }}
                }
                div { class: "search",
                    input {
                        "data-testid": "directory-search-input",
                        value: "{query}",
                        placeholder: match active_tab() {
                            DirectoryTab::Spaces => "Search spaces",
                            DirectoryTab::Organizations => "Search organizations",
                            DirectoryTab::Actors => "Search actors",
                            DirectoryTab::Handles => "Enter handle (e.g. alice.example)",
                        },
                        oninput: move |event| query.set(event.value()),
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
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match tab {
                                                DirectoryTab::Spaces => {
                                                    match api.search_spaces(&q).await {
                                                        Ok(search) => spaces.set(search.results),
                                                        Err(error) => status.set(format!("search failed: {error}")),
                                                    }
                                                }
                                                DirectoryTab::Organizations => {
                                                    match api.search_organizations(&q).await {
                                                        Ok(search) => org_results.set(search.results),
                                                        Err(error) => status.set(format!("org search failed: {error}")),
                                                    }
                                                }
                                                DirectoryTab::Actors => {
                                                    match api.search_actors(&q).await {
                                                        Ok(search) => actor_results.set(search.results),
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
            }

            // Organizations tab results
            if active_tab() == DirectoryTab::Organizations {
                for org in org_results() {
                    div { class: "event", "data-testid": "org-result",
                        div { class: "event-head",
                            span { "organization" }
                            span { "{org.get(\"id\").and_then(|v| v.as_str()).unwrap_or(\"-\")}" }
                        }
                        div { class: "space-title", "{org.get(\"name\").and_then(|v| v.as_str()).unwrap_or(\"unknown\")}" }
                        div { class: "muted", "{org.get(\"description\").and_then(|v| v.as_str()).unwrap_or(\"\")}" }
                    }
                }
                if org_results().is_empty() {
                    div { class: "event",
                        div { class: "event-head", span { "Organizations" } span { "empty" } }
                        div { class: "muted", "No organizations found. Try a search." }
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

            if !contact_status().is_empty() {
                div { class: "muted", "data-testid": "contact-status", "{contact_status}" }
            }
        }
    }
}
