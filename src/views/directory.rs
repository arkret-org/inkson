use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_navigator;
use serde_json::Value;

use crate::components::{EmptyState, EmptyStateKind, HelpTip};
use crate::models::*;
use crate::object_address::OpenedLink;
use crate::routes::Route;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::views::helpers::{display_name_for_did, short_protocol_id};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryTab {
    ProtocolObjects,
    Realms,
    Organizations,
    Actors,
    Handles,
}

#[derive(Clone, Debug, Default)]
struct PaginationState {
    realms_cursor: Option<String>,
    orgs_cursor: Option<String>,
    actors_cursor: Option<String>,
    loading_more: bool,
}

fn realm_member_count_bucket_text(bucket: &arkret_sdk::models::RealmMemberCountBucket) -> String {
    match bucket {
        arkret_sdk::models::RealmMemberCountBucket::Bucket(label) => match label {
            arkret_sdk::models::RealmMemberCountBucketLabel::OneToTen => "1-10".to_owned(),
            arkret_sdk::models::RealmMemberCountBucketLabel::ElevenToFifty => "11-50".to_owned(),
            arkret_sdk::models::RealmMemberCountBucketLabel::FiftyOneToOneHundred => {
                "51-100".to_owned()
            }
            arkret_sdk::models::RealmMemberCountBucketLabel::OneHundredOneToFiveHundred => {
                "101-500".to_owned()
            }
            arkret_sdk::models::RealmMemberCountBucketLabel::FiveHundredOneToTwoThousand => {
                "501-2000".to_owned()
            }
            arkret_sdk::models::RealmMemberCountBucketLabel::TwoThousandPlus => "2000+".to_owned(),
        },
        arkret_sdk::models::RealmMemberCountBucket::Exact(count) => count.to_string(),
    }
}

fn realm_tree_node_from_preview(preview: arkret_sdk::models::RealmPreview) -> RealmTreeNode {
    let id = preview.realm_id.as_str().to_owned();
    let alias = preview.alias.clone();
    let title = preview
        .title
        .or_else(|| alias.clone())
        .unwrap_or_else(|| id.clone());
    let mut tags = std::collections::BTreeSet::new();
    // Render the realm alias with its `#` share sigil (object-addressing.md
    // §3.3) as a directory tag so it shows alongside the title — the realm-side
    // counterpart of a user handle's `@`.
    if let Some(alias) = alias.as_deref() {
        tags.insert(format!("#{alias}"));
    }
    if let Some(discoverability) = preview.discoverability.clone() {
        tags.insert(discoverability);
    }
    if let Some(join_rule) = preview.join_rule.clone() {
        tags.insert(join_rule);
    }
    if let Some(history_visibility) = preview.history_visibility.clone() {
        tags.insert(history_visibility);
    }
    if let Some(member_count_bucket) = preview.member_count_bucket.as_ref() {
        tags.insert(format!(
            "members:{}",
            realm_member_count_bucket_text(member_count_bucket)
        ));
    }
    RealmTreeNode {
        id: id.clone(),
        title,
        description: preview.summary,
        tags,
        public: matches!(
            preview.discoverability.as_deref(),
            Some("public" | "listed")
        ),
        category: None,
        parent_space_id: None,
        child_space_ids: Vec::new(),
        kind: RealmTreeNodeKind::Realm,
        realm_id: id,
    }
}

fn organization_preview_value(preview: arkret_sdk::models::OrganizationPreview) -> Value {
    serde_json::to_value(preview).unwrap_or(Value::Null)
}

#[component]
pub fn DirectoryPanel(
    selected_realm_id: Signal<String>,
    token: Signal<String>,
    view: Signal<super::AppView>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    // (state_store: F-REMARK-FANOUT-1 — handle resolution prefers the
    // actor-private ContactRemark.local_name over the raw DID.)
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let mut active_tab = use_signal(|| DirectoryTab::Realms);
    let mut query = use_signal(String::new);
    // Local search-results scratch. Previously this view borrowed the
    // global `spaces` Signal as a write target — that overloaded the
    // sidebar's joined Realm-tree channel with directory search hits and
    // was the original reason the SyncEngine's reconcile couldn't be
    // trusted (any directory search would resurrect ghost results
    // until the next sync). Keeping the buffer local closes that hole.
    let mut realm_results = use_signal(Vec::<RealmTreeNode>::new);
    let mut org_results = use_signal(Vec::<Value>::new);
    let mut actor_results = use_signal(Vec::<Value>::new);
    let mut object_results = use_signal(Vec::<Value>::new);
    let mut handle_result = use_signal(|| Option::<ResolveHandleView>::None);
    let mut contact_target_did = use_signal(|| "did:web:bob.example".to_owned());
    let mut contact_requester_did = use_signal(|| "did:web:alice.example".to_owned());
    let mut contact_state = use_signal(|| "No contact operation yet".to_owned());
    let mut pagination = use_signal(PaginationState::default);
    // R3.3 (AKP-0011) — "Open shared link" scratch state.
    let mut open_link_input = use_signal(String::new);
    let navigator = use_navigator();
    let base_url_key = base_url.clone();

    rsx! {
        div { class: "timeline", "data-testid": "directory-panel", role: "region", "aria-label": "Search realms and people",
            // Tab bar
            div { class: "actions", "data-testid": "directory-tabs", role: "tablist", "aria-label": "Directory categories",
                Button {
                    variant: if active_tab() == DirectoryTab::Realms { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                    "data-testid": "tab-realms",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Realms { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Realms),
                    "Realms"
                }
                Button {
                    variant: if active_tab() == DirectoryTab::Organizations { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                    "data-testid": "tab-organizations",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Organizations { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Organizations),
                    "Organizations"
                }
                Button {
                    variant: if active_tab() == DirectoryTab::Actors { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                    "data-testid": "tab-actors",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Actors { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Actors),
                    "Actors"
                }
                Button {
                    variant: if active_tab() == DirectoryTab::Handles { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                    "data-testid": "tab-handles",
                    role: "tab",
                    "aria-selected": if active_tab() == DirectoryTab::Handles { "true" } else { "false" },
                    onclick: move |_| active_tab.set(DirectoryTab::Handles),
                    "Handles"
                }
            }

            details { class: "event directory-axis-card", "data-testid": "directory-three-axes-banner",
                summary { class: "event-head",
                    span { "Search Policy Axes" }
                    span { "independent decisions" }
                }
                div { class: "muted", "Discoverability, join rules, and history visibility are available here when you need policy detail." }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Discoverability" }
                        span {
                            crate::components::VisibilityPill {
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
                            crate::components::VisibilityPill {
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
                            crate::components::VisibilityPill {
                                prefix: "hist".to_owned(),
                                value: "shared_history".to_owned(),
                                kind: "history".to_owned(),
                            }
                        }
                        div { class: "muted", "what history is readable?" }
                    }
                }
                div { class: "actions", "data-testid": "permission-pill-examples",
                    crate::components::VisibilityPillRow {
                        discoverability: Some("public".to_owned()),
                        join_rule: Some("knock".to_owned()),
                        history_visibility: Some("world_readable".to_owned()),
                    }
                    span { class: "muted", "·" }
                    crate::components::VisibilityPillRow {
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
                    "Search stays focused on Realms, organizations, actors, handles, and protocol-level lookups. The old directory shortcut has been folded into the global search entrypoint."
                }
                details { class: "advanced-diagnostics", "data-testid": "directory-advanced-diagnostics",
                    summary { "data-testid": "directory-advanced-diagnostics-toggle",
                        span { "Advanced diagnostics" }
                        span { class: "badge amber", "developer tools" }
                    }
                    div { class: "muted",
                        "Protocol-object lookup is for renderer and visibility debugging. It stays collapsed by default so the end-user directory starts on normal entity search."
                    }
                    div { class: "actions",
                        Button {
                            variant: if active_tab() == DirectoryTab::ProtocolObjects { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "tab-objects",
                            role: "tab",
                            "aria-selected": if active_tab() == DirectoryTab::ProtocolObjects { "true" } else { "false" },
                            onclick: move |_| active_tab.set(DirectoryTab::ProtocolObjects),
                            "Protocol Objects"
                        }
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
                    Input {
                        "data-testid": "contact-target-did-input",
                        value: "{contact_target_did}",
                        placeholder: "Target DID",
                        oninput: move |event: FormEvent| contact_target_did.set(event.value())
                    }
                    Input {
                        "data-testid": "contact-requester-did-input",
                        value: "{contact_requester_did}",
                        placeholder: "Requester DID",
                        oninput: move |event: FormEvent| contact_requester_did.set(event.value())
                    }
                    div { class: "muted", "{contact_state}" }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
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
                                            "request {:?} {}",
                                            contact.state, contact.request_event_ref
                                        )),
                                        Err(err) => contact_state
                                            .set(format!("request: {}", err.display())),
                                    }
                                });
                            }
                        },
                        "Request"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "accept-contact-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                let requester = contact_requester_did();
                                spawn(async move {
                                    match with_authed_sdk_client(&base, api_token, |http| async move {
                                        crate::transport::account::respond_contact(&http, &requester, "accept").await
                                    })
                                    .await
                                    {
                                        Ok(contact) => contact_state.set(format!(
                                            "respond {:?} {}",
                                            contact.state, contact.response_event_ref
                                        )),
                                        Err(err) => contact_state
                                            .set(format!("accept: {}", err.display())),
                                    }
                                });
                            }
                        },
                        "Accept"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "reject-contact-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                let requester = contact_requester_did();
                                spawn(async move {
                                    match with_authed_sdk_client(&base, api_token, |http| async move {
                                        crate::transport::account::respond_contact(&http, &requester, "reject").await
                                    })
                                    .await
                                    {
                                        Ok(contact) => contact_state.set(format!(
                                            "respond {:?} {}",
                                            contact.state, contact.response_event_ref
                                        )),
                                        Err(err) => contact_state
                                            .set(format!("reject: {}", err.display())),
                                    }
                                });
                            }
                        },
                        "Reject"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "list-contacts-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                spawn(async move {
                                    match with_authed_sdk_client(&base, api_token, |http| async move {
                                        crate::transport::account::contacts(&http).await
                                    })
                                    .await
                                    {
                                        Ok(result) => {
                                            let summary = result
                                                .contacts
                                                .iter()
                                                .map(|contact| format!("{} {}", contact.peer, contact.state))
                                                .collect::<Vec<_>>()
                                                .join(", ");
                                            contact_state.set(format!("contacts {} {}", result.contacts.len(), summary));
                                        }
                                        Err(err) => contact_state.set(format!("list failed: {}", err.display())),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("directory.list_contacts")}
                    }
                }
            }

            div { class: "event directory-search-card",
                div { class: "event-head",
                    span { "Search" }
                    span { match active_tab() {
                        DirectoryTab::ProtocolObjects => "developer objects",
                        DirectoryTab::Realms => "realms",
                        DirectoryTab::Organizations => "organizations",
                        DirectoryTab::Actors => "actors",
                        DirectoryTab::Handles => "handles",
                    }}
                }
                div { class: "search",
                    Input {
                        "data-testid": "directory-search-input",
                        value: "{query}",
                        "aria-label": match active_tab() {
                            DirectoryTab::ProtocolObjects => "Search protocol objects for developer diagnostics",
                            DirectoryTab::Realms => "Search realms",
                            DirectoryTab::Organizations => "Search organizations",
                            DirectoryTab::Actors => "Search actors",
                            DirectoryTab::Handles => "Resolve handle",
                        },
                        placeholder: match active_tab() {
                            DirectoryTab::ProtocolObjects => "Search Cards, Discussions, Actors, Spaces (diagnostic lookup)",
                            DirectoryTab::Realms => "Search realms",
                            DirectoryTab::Organizations => "Search organizations",
                            DirectoryTab::Actors => "Search actors",
                            DirectoryTab::Handles => "Enter handle (e.g. alice:example.com)",
                        },
                        oninput: move |event: FormEvent| query.set(event.value()),
                        onkeydown: move |event: KeyboardEvent| {
                            if event.key().to_string() == "Enter" {
                                let base = base_url_key.clone();
                                let q = query();
                                let tab = active_tab();
                                let api_token = token();
                                pagination.write().realms_cursor = None;
                                pagination.write().orgs_cursor = None;
                                pagination.write().actors_cursor = None;
                                spawn(async move {
                                    let _ = with_authed_sdk_client(&base, api_token, |http| async move {
                                        match tab {
                                            DirectoryTab::ProtocolObjects => {
                                                object_results.set(protocol_object_results(&q));
                                            }
                                                    DirectoryTab::Realms => {
                                                        match crate::transport::directory::search_realms(&http, &q, None).await {
                                                    Ok(search) => {
                                                        pagination.write().realms_cursor = search.next_cursor.clone();
                                                        let results = search
                                                            .realms
                                                            .into_iter()
                                                            .map(realm_tree_node_from_preview)
                                                            .collect::<Vec<_>>();
                                                        realm_results.set(results);
                                                    }
                                                    Err(error) => crate::components::feedback::toast_error(
                                                        "feedback.directory_search_failed",
                                                        vec![],
                                                        Some(error.to_string()),
                                                    ),
                                                }
                                            }
                                            DirectoryTab::Organizations => {
                                                match crate::transport::directory::search_organizations(&http, &q, None).await {
                                                    Ok(search) => {
                                                        pagination.write().orgs_cursor = search.next_cursor.clone();
                                                        org_results.set(
                                                            search
                                                                .organizations
                                                                .into_iter()
                                                                .map(organization_preview_value)
                                                                .collect(),
                                                        );
                                                    }
                                                    Err(error) => crate::components::feedback::toast_error(
                                                        "feedback.directory_search_failed",
                                                        vec![],
                                                        Some(error.to_string()),
                                                    ),
                                                }
                                            }
                                            DirectoryTab::Actors => {
                                                match crate::transport::directory::search_actors(&http, &q, None).await {
                                                    Ok(search) => {
                                                        pagination.write().actors_cursor = search.next_cursor.clone();
                                                        actor_results.set(
                                                            search
                                                                .actors
                                                                .into_iter()
                                                                .map(|actor| actor.preview)
                                                                .collect(),
                                                        );
                                                    }
                                                    Err(error) => crate::components::feedback::toast_error(
                                                        "feedback.directory_search_failed",
                                                        vec![],
                                                        Some(error.to_string()),
                                                    ),
                                                }
                                            }
                                            DirectoryTab::Handles => {
                                                match crate::transport::directory::resolve_handle(&http, &q).await {
                                                    Ok(resolved) => handle_result.set(Some(resolved)),
                                                    Err(error) => crate::components::feedback::toast_error(
                                                        "feedback.directory_resolve_failed",
                                                        vec![],
                                                        Some(error.to_string()),
                                                    ),
                                                }
                                            }
                                        }
                                        Ok::<_, anyhow::Error>(())
                                    })
                                    .await;
                                });
                            }
                        },
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "directory-search-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let base = base.clone();
                                    let q = query();
                                    let tab = active_tab();
                                    let api_token = token();
                                    pagination.write().realms_cursor = None;
                                    pagination.write().orgs_cursor = None;
                                    pagination.write().actors_cursor = None;
                                    spawn(async move {
                                        let _ = with_authed_sdk_client(&base, api_token, |http| async move {
                                            match tab {
                                                DirectoryTab::ProtocolObjects => {
                                                    object_results.set(protocol_object_results(&q));
                                                }
                                                DirectoryTab::Realms => {
                                                    match crate::transport::directory::search_realms(&http, &q, None).await {
                                                        Ok(search) => {
                                                            pagination.write().realms_cursor = search.next_cursor.clone();
                                                            let results = search
                                                                .realms
                                                                .into_iter()
                                                                .map(realm_tree_node_from_preview)
                                                                .collect::<Vec<_>>();
                                                            realm_results.set(results);
                                                        }
                                                        Err(error) => crate::components::feedback::toast_error(
                                                            "feedback.directory_search_failed",
                                                            vec![],
                                                            Some(error.to_string()),
                                                        ),
                                                    }
                                                }
                                                DirectoryTab::Organizations => {
                                                    match crate::transport::directory::search_organizations(&http, &q, None).await {
                                                        Ok(search) => {
                                                            pagination.write().orgs_cursor = search.next_cursor.clone();
                                                            org_results.set(
                                                                search
                                                                    .organizations
                                                                    .into_iter()
                                                                    .map(organization_preview_value)
                                                                    .collect(),
                                                            );
                                                        }
                                                        Err(error) => crate::components::feedback::toast_error(
                                                            "feedback.directory_search_failed",
                                                            vec![],
                                                            Some(error.to_string()),
                                                        ),
                                                    }
                                                }
                                                DirectoryTab::Actors => {
                                                    match crate::transport::directory::search_actors(&http, &q, None).await {
                                                        Ok(search) => {
                                                            pagination.write().actors_cursor = search.next_cursor.clone();
                                                            actor_results.set(
                                                                search
                                                                    .actors
                                                                    .into_iter()
                                                                    .map(|actor| actor.preview)
                                                                    .collect(),
                                                            );
                                                        }
                                                        Err(error) => crate::components::feedback::toast_error(
                                                            "feedback.directory_search_failed",
                                                            vec![],
                                                            Some(error.to_string()),
                                                        ),
                                                    }
                                                }
                                                DirectoryTab::Handles => {
                                                    match crate::transport::directory::resolve_handle(&http, &q).await {
                                                        Ok(resolved) => handle_result.set(Some(resolved)),
                                                        Err(error) => crate::components::feedback::toast_error(
                                                            "feedback.directory_resolve_failed",
                                                            vec![],
                                                            Some(error.to_string()),
                                                        ),
                                                    }
                                                }
                                            }
                                            Ok::<_, anyhow::Error>(())
                                        })
                                        .await;
                                    });
                                }
                            },
                            {crate::i18n::tr("directory.search_button")}
                        }
                        if active_tab() == DirectoryTab::Realms {
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "resolve-selected-button",
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let id = selected_realm_id();
                                        let api_token = token();
                                        spawn(async move {
                                            match with_authed_sdk_client(&base, api_token, |http| async move {
                                                crate::transport::directory::resolve_realm(&http, &id).await
                                            })
                                            .await
                                            {
                                                Ok(resolved) => {
                                                    selected_realm_id.set(
                                                        resolved.realm_preview.realm_id.as_str().to_owned(),
                                                    );
                                                    crate::components::feedback::toast_success(
                                                        "feedback.realm_resolved",
                                                        vec![(
                                                            "join_rule",
                                                            format!("{:?}", resolved.join_rule),
                                                        )],
                                                    );
                                                }
                                                Err(err) => crate::components::feedback::toast_error(
                                                    "feedback.directory_resolve_failed",
                                                    vec![],
                                                    Some(err.display()),
                                                ),
                                            }
                                        });
                                    }
                                },
                                {crate::i18n::tr("directory.resolve_selected")}
                            }
                        }
                    }
                }
            }

            // R3.3 (AKP-0011) — "Open shared link" entry point. Accepts a
            // pasted `web+arkret:` or HTTPS-fragment link, resolves it via
            // `directory_resolve_target`, and routes to the local UI by
            // `target_kind`. Failures collapse to one friendly message
            // (never distinguish not_found vs unauthorized).
            // TODO(R3.3.1): a richer share/open surface (per-object "Share"
            // context-menu actions in the Board and Realm pages, an
            // invite-token issuance strand, and a confirm-before-navigate
            // preview card) lives here in a follow-up.
            div { class: "event", "data-testid": "open-shared-link",
                div { class: "event-head",
                    span { {crate::i18n::tr("object_link.open")} }
                    HelpTip { text: "Paste a Arkret share link to open the Realm, Strand, or Message it points at." }
                }
                div { class: "actions",
                    Input {
                        r#type: "text",
                        "data-testid": "open-link-input",
                        placeholder: crate::i18n::tr("object_link.open_placeholder"),
                        value: "{open_link_input}",
                        oninput: move |event: FormEvent| open_link_input.set(event.value()),
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "open-link-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let raw = open_link_input();
                                if raw.trim().is_empty() {
                                    return;
                                }
                                // Parse + fail closed locally before any network call.
                                let opened = match OpenedLink::parse(&raw) {
                                    Ok(opened) => opened,
                                    Err(_) => {
                                        crate::components::feedback::toast_error(
                                            "object_link.error.invalid",
                                            vec![],
                                            None,
                                        );
                                        return;
                                    }
                                };
                                let base = base.clone();
                                let api_token = token();
                                let navigator = navigator;
                                crate::components::feedback::toast_info("object_link.opening", vec![]);
                                spawn(async move {
                                    let address = opened.resolve_address();
                                    let token_arg = opened.token.clone();
                                    let resolved = with_authed_sdk_client(&base, api_token, |http| async move {
                                        crate::transport::directory::directory_resolve_target(&http, &address, token_arg.as_deref())
                                            .await
                                    })
                                    .await;
                                    match resolved {
                                        Ok(res) => {
                                            let route = opened.route_for(res.target_kind);
                                            navigator.push(route);
                                        }
                                        // Anti-enumeration: every failure is the
                                        // same friendly message.
                                        Err(_) => crate::components::feedback::toast_error(
                                            "object_link.error.unavailable",
                                            vec![],
                                            None,
                                        ),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("object_link.open")}
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
                        // Stable list key: use a stable object identifier
                        // (target_ref/id/did), falling back to title, so a
                        // missing key doesn't force the whole list to rebuild.
                        ProtocolObjectResult {
                            key: "{value_str_any(&result, &[\"target_ref\", \"id\", \"did\"], json_text(&result, \"title\").as_str())}",
                            result,
                        }
                    }
                }
            }

            // Realm directory results
            if active_tab() == DirectoryTab::Realms {
                for realm in realm_results() {
                    div {
                        key: "{realm.id}", // Stable list key: realm business id.
                        class: "event",
                        "data-testid": "directory-result",
                        div { class: "event-head",
                            span { "{realm.category.clone().unwrap_or_else(|| \"realm\".to_owned())}" }
                            span { if realm.public { "public" } else { "private" } }
                        }
                        div { class: "entity-title", "{realm.title}" }
                        div { class: "muted", "{realm.description.clone().unwrap_or_default()}" }
                        div { class: "actions",
                            Link {
                                class: "primary",
                                "data-testid": "open-realm-button",
                                to: Route::Realm { realm_id: realm.id.clone() },
                                onclick: {
                                    let id = realm.id.clone();
                                    move |_| {
                                        selected_realm_id.set(id.clone());
                                        view.set(super::AppView::Kanban);
                                    }
                                },
                                "Open Realm"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "directory-select-button",
                                onclick: {
                                    let id = realm.id.clone();
                                    move |_| selected_realm_id.set(id.clone())
                                },
                                "Select"
                            }
                        }
                    }
                }
                if !realm_results().is_empty() {
                    div { class: "event", "data-testid": "index-query-results",
                        div { class: "event-head", span { "Index Projection" } span { "{realm_results().len()} result(s)" } }
                        for realm in realm_results() {
                            GenericEntityCard {
                                key: "{realm.id}", // Stable list key: realm business id (as above).
                                title: realm.title.clone(),
                                summary: realm.description.clone().unwrap_or_else(|| "Realm projection".to_owned()),
                                entity_type: "realm".to_owned(),
                            }
                        }
                    }
                }
                if pagination().realms_cursor.is_some() {
                    div { class: "event",
                        div { class: "actions",
                            if pagination().realms_cursor.is_some() {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "load-more-realms",
                                    disabled: pagination().loading_more,
                                    onclick: {
                                        let base = base_url.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let q = query();
                                            let api_token = token();
                                            let cursor = pagination.read().realms_cursor.clone();
                                            pagination.write().loading_more = true;
                                            spawn(async move {
                                                match with_authed_sdk_client(&base, api_token, |http| async move {
                                                    crate::transport::directory::search_realms(&http, &q, cursor.as_deref()).await
                                                })
                                                .await
                                                {
                                                    Ok(search) => {
                                                        pagination.write().realms_cursor = search.next_cursor.clone();
                                                        let mut current = realm_results();
                                                        current.extend(
                                                            search
                                                                .realms
                                                                .into_iter()
                                                                .map(realm_tree_node_from_preview),
                                                        );
                                                        realm_results.set(current);
                                                    }
                                                    Err(err) => crate::components::feedback::toast_error(
                                                        "feedback.directory_load_more_failed",
                                                        vec![],
                                                        Some(err.display()),
                                                    ),
                                                }
                                                pagination.write().loading_more = false;
                                            });
                                        }
                                    },
                                    if pagination().loading_more {
                                        {crate::i18n::tr("directory.loading_more")}
                                    } else {
                                        {crate::i18n::tr("directory.load_more_realms")}
                                    }
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
                        let org_id = value_str_any(&org, &["organization_id", "id"], "-");
                        let org_did = value_str_any(&org, &["organization_did", "did"], org_id.as_str());
                        let org_name = value_str_any(&org, &["display_name", "name"], "unknown");
                        let org_description = value_str(&org, "description", "");
                        let org_handle = value_str(&org, "handle", "");
                        let discoverability = value_str(&org, "discoverability", "unknown");
                        let profile_visibility = value_str(&org, "profile_visibility", "unknown");
                        let directory_services = value_vec(&org, "directory_services");
                        let proof_count = value_vec(&org, "proofs").len();
                        // YGN-ORG-04: a single `verified` bool is not enough —
                        // show the proof-backed relationship the organization
                        // statement asserts (owner / governance /
                        // directory_certifier), and never show an official
                        // badge for a stale / revoked / expired projection.
                        let verified_relationships = verified_org_relationships(&org);
                        let member_count = value_count_any(&org, &["member_count", "actor_count", "members"]);
                        let realm_count = value_count_any(&org, &["realm_count", "realms"]);
                        let inheritance_hint = if realm_count > 0 {
                            format!("Policy inheritance: active across {realm_count} realm(s)")
                        } else {
                            "Policy inheritance: no linked realms".to_owned()
                        };
                        let org_did_label = short_protocol_id(&org_did);
                        let actor_lookup_seed = if !org_handle.is_empty() {
                            org_handle.clone()
                        } else {
                            org_name.clone()
                        };
                        rsx! {
                            div {
                                key: "{org_id}", // Stable list key: organization business id.
                                class: "event",
                                "data-testid": "org-result",
                                "data-organization-id": "{org_id}",
                                "data-organization-did": "{org_did}",
                                div { class: "event-head",
                                    span { "organization" }
                                    span { title: "{org_did}", "{org_did_label}" }
                                }
                                div { class: "entity-title",
                                    "{org_name}"
                                    // Proof-backed relationship badges. Each badge
                                    // names the relationship the organization
                                    // signed (owner / governance /
                                    // directory_certifier); a declared-only or
                                    // stale / revoked / expired projection yields
                                    // no badge at all.
                                    for relationship in verified_relationships.clone() {
                                        span {
                                            class: "badge badge-success",
                                            style: "margin-left: 8px;",
                                            title: "Proof-backed organization relationship",
                                            "data-testid": "organization-verified-badge",
                                            "data-relationship": "{relationship}",
                                            "{relationship}"
                                        }
                                    }
                                }
                                if !org_handle.is_empty() {
                                    div { class: "muted", "Handle: {org_handle}" }
                                }
                                div { class: "muted", "{org_description}" }
                                div { class: "actions",
                                    span {
                                        class: "badge badge-info",
                                        "data-testid": "organization-member-count",
                                        "{member_count} member(s)"
                                    }
                                    span {
                                        class: if realm_count > 0 { "badge badge-success" } else { "badge badge-info" },
                                        "data-testid": "organization-policy-hint",
                                        "{inheritance_hint}"
                                    }
                                    span { class: "badge badge-info", "Discoverability: {discoverability}" }
                                    span { class: "badge badge-info", "Profile: {profile_visibility}" }
                                    span { class: "badge badge-success", "{directory_services.len()} directory service(s)" }
                                    span { class: "badge badge-warning", "{proof_count} proof(s)" }
                                }
                                if !directory_services.is_empty() {
                                    div { class: "muted", "Directory services: {directory_services.join(\", \")}" }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
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
                                        Button {
                                            variant: ButtonVariant::Secondary,
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
                            Button {
                                variant: ButtonVariant::Secondary,
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
                                            match with_authed_sdk_client(&base, api_token, |http| async move {
                                                crate::transport::directory::search_organizations(&http, &q, cursor.as_deref()).await
                                            })
                                            .await
                                            {
                                                Ok(search) => {
                                                    pagination.write().orgs_cursor = search.next_cursor.clone();
                                                    let mut current = org_results();
                                                    current.extend(
                                                            search
                                                                .organizations
                                                                .into_iter()
                                                                .map(organization_preview_value),
                                                    );
                                                    org_results.set(current);
                                                }
                                                Err(err) => crate::components::feedback::toast_error(
                                                    "feedback.directory_load_more_failed",
                                                    vec![],
                                                    Some(err.display()),
                                                ),
                                            }
                                            pagination.write().loading_more = false;
                                        });
                                    }
                                },
                                if pagination().loading_more {
                                    {crate::i18n::tr("directory.loading_more")}
                                } else {
                                    {crate::i18n::tr("directory.load_more_organizations")}
                                }
                            }
                        }
                    }
                }
            }

            // Actors tab results
            if active_tab() == DirectoryTab::Actors {
                for actor in actor_results() {
                    div {
                        // Stable list key: the actor's did (falls back to the "-" placeholder).
                        key: "{actor.get(\"did\").and_then(|v| v.as_str()).unwrap_or(\"-\")}",
                        class: "event",
                        "data-testid": "actor-result",
                        div { class: "event-head",
                            span { "actor" }
                            {
                                let actor_id = actor
                                    .get("did")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("-")
                                    .to_owned();
                                let actor_id_label =
                                    display_name_for_did(&state_store.read(), &actor_id);
                                rsx! {
                                    span { title: "{actor_id}", "{actor_id_label}" }
                                }
                            }
                        }
                        div { class: "actions", style: "align-items: center; gap: 12px;",
                            // A4b — directory actor avatar. soland's
                            // `search-actors` projection echoes
                            // `avatar_url` straight from the
                            // `AccountRecord` so we can render it
                            // without an extra round trip.
                            {
                                let avatar_url = actor
                                    .get("avatar_url")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                rsx! {
                                    if !avatar_url.trim().is_empty() {
                                        img {
                                            class: "avatar-img sm",
                                            "data-testid": "directory-actor-avatar",
                                            src: "{avatar_url}",
                                            alt: "Avatar",
                                        }
                                    } else {
                                        div {
                                            class: "avatar-img sm placeholder",
                                            "data-testid": "directory-actor-avatar",
                                            "aria-hidden": "true",
                                        }
                                    }
                                }
                            }
                            div {
                                div { class: "entity-title", "{actor.get(\"handle\").and_then(|v| v.as_str()).unwrap_or(\"unknown\")}" }
                                div { class: "muted", "{actor.get(\"display_name\").and_then(|v| v.as_str()).unwrap_or(\"\")}" }
                            }
                            // G3.Y3 — directory-side `block-actor-button`.
                            // Navigates to the blocklist settings page
                            // with the target DID prefilled via the
                            // local state store, so the cotest
                            // `personal-blocklist` scenario can pick a
                            // peer from search results and block them
                            // without typing the DID by hand.
                            //
                            // TODO(G3.Y3-followup): replace the route-only
                            // hop with an in-place block confirmation
                            // overlay once the soland account_data
                            // `POST /_arkret/self/account-data/blocklist`
                            // endpoint exists; today the click is just a
                            // shortcut into `/settings/blocklist`.
                            {
                                let actor_id = actor
                                    .get("did")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_owned();
                                rsx! {
                                    Link {
                                        class: "secondary",
                                        "data-testid": "block-actor-button",
                                        "data-actor-did": "{actor_id}",
                                        to: Route::SettingsSection { section: "blocklist".to_owned() },
                                        "Block"
                                    }
                                }
                            }
                            {
                                // TSP is an interop extension profile: external
                                // VID endpoints can be reached over a TSP
                                // relationship managed under /settings/connections.
                                let actor_id = actor
                                    .get("did")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_owned();
                                rsx! {
                                    Link {
                                        class: "secondary",
                                        "data-testid": "establish-tsp-button",
                                        "data-remote-vid": "{actor_id}",
                                        to: Route::SettingsSection { section: "connections".to_owned() },
                                        "Establish TSP"
                                    }
                                }
                            }
                            {
                                let actor_id = actor
                                    .get("did")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_owned();
                                let actor_id_label =
                                    display_name_for_did(&state_store.read(), &actor_id);
                                rsx! {
                                    div {
                                        class: "muted",
                                        "data-testid": "actor-result-did",
                                        title: "{actor_id}",
                                        "{actor_id_label}"
                                    }
                                }
                            }
                        }
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
                            Button {
                                variant: ButtonVariant::Secondary,
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
                                            match with_authed_sdk_client(&base, api_token, |http| async move {
                                                crate::transport::directory::search_actors(&http, &q, cursor.as_deref()).await
                                            })
                                            .await
                                            {
                                                Ok(search) => {
                                                    pagination.write().actors_cursor = search.next_cursor.clone();
                                                    let mut current = actor_results();
                                                    current.extend(
                                                        search
                                                            .actors
                                                            .into_iter()
                                                            .map(|actor| actor.preview),
                                                    );
                                                    actor_results.set(current);
                                                }
                                                Err(err) => crate::components::feedback::toast_error(
                                                    "feedback.directory_load_more_failed",
                                                    vec![],
                                                    Some(err.display()),
                                                ),
                                            }
                                            pagination.write().loading_more = false;
                                        });
                                    }
                                },
                                if pagination().loading_more {
                                    {crate::i18n::tr("directory.loading_more")}
                                } else {
                                    {crate::i18n::tr("directory.load_more_actors")}
                                }
                            }
                        }
                    }
                }
            }

            // Handles tab result
            if active_tab() == DirectoryTab::Handles {
                if let Some(ref resolved) = handle_result() {
                    {
                        // F-REMARK-FANOUT-1: surface the user's chosen alias
                        // (if any) for the resolved DID, with the canonical
                        // DID kept verbatim in `title` for verification.
                        let resolved_display =
                            display_name_for_did(&state_store.read(), &resolved.did);
                        let resolved_did_attr = resolved.did.clone();
                        let resolved_did_document = resolved.did_document.clone();
                        rsx! {
                            div { class: "event", "data-testid": "handle-result",
                                div { class: "event-head",
                                    span { "Resolved" }
                                    span { "{resolved.handle}" }
                                }
                                div { class: "entity-title", title: "{resolved_did_attr}", "{resolved_display}" }
                                if let Some(doc) = resolved_did_document {
                                    div { class: "muted", "DID document loaded" }
                                    div { class: "muted", "{doc}" }
                                }
                            }
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

fn value_str_any(value: &Value, keys: &[&str], fallback: impl Into<String>) -> String {
    keys.iter()
        .find_map(|key| {
            value
                .get(*key)
                .and_then(|value| value.as_str())
                .filter(|text| !text.trim().is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| fallback.into())
}

fn value_bool_any(value: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(|value| value.as_bool()))
        .unwrap_or(false)
}

/// YGN-ORG-04 — derive the proof-backed organization relationships to badge
/// from a directory organization preview.
///
/// Returns the relationship names (`owner` / `governance` /
/// `directory_certifier`) the organization has a live, proof-backed statement
/// for. A `sponsor` relationship is intentionally NOT an official directory
/// badge. The result is empty (no official badge) when:
///   - the projection is `stale` or `divergent`, or
///   - a relationship is revoked / inactive / expired, or
///   - the preview only carries a declared hint (no proof-backed relationship).
///
/// The legacy single `verified_badge` / `verified` bool is deliberately NOT
/// honored on its own: a bare bool cannot distinguish a declared hint from a
/// verified relationship, which is exactly the confusion this task removes.
/// Field names align with the forthcoming teabay / soland projection
/// (TBY-ORG-02): a `verified_relationships` array of
/// `{relationship, status, expires_at}` objects.
fn verified_org_relationships(org: &Value) -> Vec<String> {
    // A stale / divergent projection is never authoritative enough to badge.
    if value_bool_any(org, &["stale"]) || value_bool_any(org, &["divergent"]) {
        return Vec::new();
    }

    let now = crate::clock::now_rfc3339_secs();
    let mut out = Vec::new();
    if let Some(entries) = org
        .get("verified_relationships")
        .and_then(|value| value.as_array())
    {
        for entry in entries {
            let relationship = entry
                .get("relationship")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if !is_official_badge_relationship(relationship) {
                continue;
            }
            // status defaults to active when omitted; anything other than
            // "active" (revoked / pending / etc.) does not badge.
            let status = entry
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("active");
            if status != "active" {
                continue;
            }
            // expired statements lose the badge. `expires_at` is an RFC3339
            // string; absence means no expiry.
            if let Some(expires_at) = entry.get("expires_at").and_then(|value| value.as_str()) {
                if !expires_at.is_empty() && expires_at <= now.as_str() {
                    continue;
                }
            }
            if !out.iter().any(|existing| existing == relationship) {
                out.push(relationship.to_owned());
            }
        }
    }
    out
}

fn is_official_badge_relationship(relationship: &str) -> bool {
    matches!(relationship, "owner" | "governance" | "directory_certifier")
}

fn value_count_any(value: &Value, keys: &[&str]) -> usize {
    keys.iter()
        .find_map(|key| {
            let current = value.get(*key)?;
            if let Some(count) = current.as_u64() {
                return Some(count as usize);
            }
            current.as_array().map(Vec::len)
        })
        .unwrap_or(0)
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
            div { class: "entity-title", "{title}" }
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
            div { class: "entity-title", "{title}" }
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
            "summary": "Discussion projection with history_visibility=shared and linked strand metadata.",
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn declared_only_org_gets_no_verified_badge() {
        // YGN-ORG-04 acceptance: a declared-only Realm/organization with no
        // proof-backed relationship array shows no verified badge.
        let org = json!({
            "organization_did": "did:web:hint.example",
            "display_name": "Hinted Org",
            // Legacy bool is intentionally ignored on its own.
            "verified_badge": true,
        });
        assert!(verified_org_relationships(&org).is_empty());
    }

    #[test]
    fn active_relationships_are_badged() {
        let org = json!({
            "organization_did": "did:web:acme.example",
            "verified_relationships": [
                { "relationship": "owner", "status": "active" },
                { "relationship": "governance", "status": "active" },
            ],
        });
        let rels = verified_org_relationships(&org);
        assert!(rels.contains(&"owner".to_owned()));
        assert!(rels.contains(&"governance".to_owned()));
    }

    #[test]
    fn sponsor_is_not_an_official_badge() {
        let org = json!({
            "verified_relationships": [
                { "relationship": "sponsor", "status": "active" },
            ],
        });
        assert!(verified_org_relationships(&org).is_empty());
    }

    #[test]
    fn revoked_or_expired_relationships_drop_the_badge() {
        let org = json!({
            "verified_relationships": [
                { "relationship": "owner", "status": "revoked" },
                { "relationship": "governance", "status": "active", "expires_at": "2000-01-01T00:00:00Z" },
            ],
        });
        assert!(verified_org_relationships(&org).is_empty());
    }

    #[test]
    fn stale_or_divergent_projection_drops_all_badges() {
        let stale = json!({
            "stale": true,
            "verified_relationships": [
                { "relationship": "owner", "status": "active" },
            ],
        });
        assert!(verified_org_relationships(&stale).is_empty());

        let divergent = json!({
            "divergent": true,
            "verified_relationships": [
                { "relationship": "owner", "status": "active" },
            ],
        });
        assert!(verified_org_relationships(&divergent).is_empty());
    }

    #[test]
    fn far_future_expiry_keeps_the_badge() {
        let org = json!({
            "verified_relationships": [
                { "relationship": "directory_certifier", "status": "active", "expires_at": "9999-01-01T00:00:00Z" },
            ],
        });
        assert_eq!(
            verified_org_relationships(&org),
            vec!["directory_certifier".to_owned()]
        );
    }
}
