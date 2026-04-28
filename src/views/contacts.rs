use dioxus::prelude::*;
use serde_json::Value;

use crate::{
    api::ContrixApi,
    models::*,
    views::helpers::authed_api,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContactTab {
    Search,
    Incoming,
    Outgoing,
    All,
    Blocked,
}

#[component]
pub fn ContactsPanel(
    base_url: String,
    token: Signal<String>,
) -> Element {
    let mut active_tab = use_signal(|| ContactTab::All);
    let mut search_query = use_signal(String::new);
    let mut search_results = use_signal(Vec::<Value>::new);
    let mut all_contacts = use_signal(Vec::<ContactResponse>::new);
    let mut incoming_requests = use_signal(Vec::<ContactResponse>::new);
    let mut outgoing_requests = use_signal(Vec::<ContactResponse>::new);
    let mut contact_note = use_signal(String::new);
    let mut status_msg = use_signal(|| String::new());
    let mut detail_contact = use_signal(|| Option::<ContactResponse>::None);

    rsx! {
        div { class: "timeline", "data-testid": "contacts-panel",
            // Tab bar
            div { class: "actions", "data-testid": "contacts-tabs",
                button {
                    class: if active_tab() == ContactTab::All { "primary" } else { "secondary" },
                    "data-testid": "tab-all",
                    onclick: move |_| {
                        active_tab.set(ContactTab::All);
                        let base = base_url.clone();
                        let api_token = token();
                        spawn(async move {
                            if let Ok(api) = authed_api(&base, api_token) {
                                match api.list_contacts().await {
                                    Ok(resp) => all_contacts.set(resp.contacts),
                                    Err(e) => status_msg.set(format!("list failed: {e}")),
                                }
                            }
                        });
                    },
                    "All Contacts"
                }
                button {
                    class: if active_tab() == ContactTab::Search { "primary" } else { "secondary" },
                    "data-testid": "tab-search",
                    onclick: move |_| active_tab.set(ContactTab::Search),
                    "Search"
                }
                button {
                    class: if active_tab() == ContactTab::Incoming { "primary" } else { "secondary" },
                    "data-testid": "tab-incoming",
                    onclick: move |_| active_tab.set(ContactTab::Incoming),
                    "Incoming"
                }
                button {
                    class: if active_tab() == ContactTab::Outgoing { "primary" } else { "secondary" },
                    "data-testid": "tab-outgoing",
                    onclick: move |_| active_tab.set(ContactTab::Outgoing),
                    "Outgoing"
                }
                button {
                    class: if active_tab() == ContactTab::Blocked { "primary" } else { "secondary" },
                    "data-testid": "tab-blocked",
                    onclick: move |_| active_tab.set(ContactTab::Blocked),
                    "Blocked"
                }
            }

            // Search tab
            if active_tab() == ContactTab::Search {
                div { class: "event", "data-testid": "contact-search",
                    div { class: "event-head", span { "Search" } span { "DID / handle" } }
                    div { class: "search",
                        input {
                            "data-testid": "contact-search-input",
                            value: "{search_query}",
                            placeholder: "Enter DID or handle",
                            oninput: move |evt| search_query.set(evt.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "contact-search-button",
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let q = search_query();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.search_users(&q).await {
                                                    Ok(resp) => search_results.set(resp.results),
                                                    Err(e) => status_msg.set(format!("search failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Search"
                            }
                        }
                    }
                    // Note input
                    div { class: "workflow-form",
                        label { "Note (optional)" }
                        input {
                            "data-testid": "contact-note-input",
                            value: "{contact_note}",
                            placeholder: "Hi, I'd like to connect...",
                            oninput: move |evt| contact_note.set(evt.value()),
                        }
                    }
                    for result in search_results() {
                        div { class: "event", "data-testid": "search-result",
                            div { class: "event-head",
                                span { "{result.get(\"did\").and_then(|v| v.as_str()).unwrap_or(\"unknown\")}" }
                                span { "" }
                            }
                            div { class: "space-title",
                                "{result.get(\"handle\").and_then(|v| v.as_str()).unwrap_or(\"\")}"
                            }
                            div { class: "muted",
                                "{result.get(\"display_name\").and_then(|v| v.as_str()).unwrap_or(\"\")}"
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "send-contact-request",
                                    onclick: {
                                        let base = base_url.clone();
                                        let target = result.get("did").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                                        move |_| {
                                            let base = base.clone();
                                            let target = target.clone();
                                            let api_token = token();
                                            spawn(async move {
                                                if let Ok(api) = authed_api(&base, api_token) {
                                                    match api.request_contact(&target).await {
                                                        Ok(c) => status_msg.set(format!("sent to {} ({})", c.target, c.status)),
                                                        Err(e) => status_msg.set(format!("request failed: {e}")),
                                                    }
                                                }
                                            });
                                        }
                                    },
                                    "Send Request"
                                }
                            }
                        }
                    }
                }
            }

            // Incoming requests
            if active_tab() == ContactTab::Incoming {
                div { class: "event", "data-testid": "incoming-requests",
                    div { class: "event-head", span { "Incoming Requests" } span { "{incoming_requests().len()}" } }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "refresh-incoming",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let base = base.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.list_contacts().await {
                                                Ok(resp) => {
                                                    let incoming: Vec<_> = resp.contacts.into_iter()
                                                        .filter(|c| c.status == "pending")
                                                        .collect();
                                                    incoming_requests.set(incoming);
                                                }
                                                Err(e) => status_msg.set(format!("list failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Refresh"
                        }
                    }
                    for contact in incoming_requests() {
                        div { class: "event", "data-testid": "incoming-request",
                            div { class: "event-head",
                                span { "{contact.requester}" }
                                span { "{contact.status}" }
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "accept-request-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let requester = contact.requester.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let requester = requester.clone();
                                            let api_token = token();
                                            spawn(async move {
                                                if let Ok(api) = authed_api(&base, api_token) {
                                                    match api.respond_contact(&requester, "accept").await {
                                                        Ok(c) => status_msg.set(format!("accepted {}", c.requester)),
                                                        Err(e) => status_msg.set(format!("accept failed: {e}")),
                                                    }
                                                }
                                            });
                                        }
                                    },
                                    "Accept"
                                }
                                button {
                                    class: "secondary",
                                    "data-testid": "reject-request-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let requester = contact.requester.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let requester = requester.clone();
                                            let api_token = token();
                                            spawn(async move {
                                                if let Ok(api) = authed_api(&base, api_token) {
                                                    match api.respond_contact(&requester, "reject").await {
                                                        Ok(c) => status_msg.set(format!("rejected {}", c.requester)),
                                                        Err(e) => status_msg.set(format!("reject failed: {e}")),
                                                    }
                                                }
                                            });
                                        }
                                    },
                                    "Reject"
                                }
                                button {
                                    class: "secondary",
                                    "data-testid": "block-request-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let requester = contact.requester.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let requester = requester.clone();
                                            let api_token = token();
                                            spawn(async move {
                                                if let Ok(api) = authed_api(&base, api_token) {
                                                    match api.respond_contact(&requester, "block").await {
                                                        Ok(c) => status_msg.set(format!("blocked {}", c.requester)),
                                                        Err(e) => status_msg.set(format!("block failed: {e}")),
                                                    }
                                                }
                                            });
                                        }
                                    },
                                    "Block"
                                }
                            }
                        }
                    }
                    if incoming_requests().is_empty() {
                        div { class: "muted", "No incoming requests." }
                    }
                }
            }

            // Outgoing requests
            if active_tab() == ContactTab::Outgoing {
                div { class: "event", "data-testid": "outgoing-requests",
                    div { class: "event-head", span { "Outgoing Requests" } span { "{outgoing_requests().len()}" } }
                    for contact in outgoing_requests() {
                        div { class: "event", "data-testid": "outgoing-request",
                            div { class: "event-head",
                                span { "{contact.target}" }
                                span { "{contact.status}" }
                            }
                            div { class: "actions",
                                button {
                                    class: "secondary",
                                    "data-testid": "cancel-request-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let target = contact.target.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let target = target.clone();
                                            let api_token = token();
                                            spawn(async move {
                                                if let Ok(api) = authed_api(&base, api_token) {
                                                    let _ = api.respond_contact(&target, "cancel").await;
                                                }
                                            });
                                        }
                                    },
                                    "Cancel"
                                }
                            }
                        }
                    }
                    if outgoing_requests().is_empty() {
                        div { class: "muted", "No outgoing requests." }
                    }
                }
            }

            // All contacts
            if active_tab() == ContactTab::All {
                for contact in all_contacts() {
                    div { class: "event", "data-testid": "contact-entry",
                        div { class: "event-head",
                            span { "{contact.target}" }
                            span { "{contact.status}" }
                        }
                        div { class: "muted", "Requested: {contact.created_at}" }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "view-contact-detail",
                                onclick: {
                                    let c = contact.clone();
                                    move |_| detail_contact.set(Some(c.clone()))
                                },
                                "Details"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "block-contact-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let target = contact.target.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let target = target.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                let _ = api.respond_contact(&target, "block").await;
                                            }
                                        });
                                    }
                                },
                                "Block"
                            }
                        }
                    }
                }
                if all_contacts().is_empty() {
                    div { class: "muted", "No contacts loaded. Click All Contacts tab to refresh." }
                }
            }

            // Blocked tab
            if active_tab() == ContactTab::Blocked {
                div { class: "event",
                    div { class: "event-head", span { "Blocked" } span { "" } }
                    div { class: "muted", "Blocked contacts will appear here. Use the contact list to manage blocks." }
                }
            }

            // Contact detail view
            if let Some(ref detail) = detail_contact() {
                div { class: "event", "data-testid": "contact-detail",
                    div { class: "event-head",
                        span { "Contact Detail" }
                        span { "{detail.status}" }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Target" }
                            span { "{detail.target}" }
                        }
                        div { class: "metric",
                            strong { "Requester" }
                            span { "{detail.requester}" }
                        }
                        div { class: "metric",
                            strong { "Created" }
                            span { "{detail.created_at}" }
                        }
                        div { class: "metric",
                            strong { "Updated" }
                            span { "{detail.updated_at}" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            onclick: move |_| detail_contact.set(None),
                            "Close"
                        }
                    }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "contacts-status", "{status_msg}" }
            }
        }
    }
}
