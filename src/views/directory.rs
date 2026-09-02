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
use crate::views::helpers::{actor_display_label, short_protocol_id};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryTab {
    Realms,
    Organizations,
    Actors,
    Handles,
}

fn contact_operation_status(
    outcome: &arkret_sdk::contact_operations::ContactOperationOutcome,
) -> &'static str {
    use arkret_sdk::contact_operations::{ContactAcceptedOutcome, ContactOperationOutcome};

    match outcome {
        ContactOperationOutcome::Accepted {
            outcome: ContactAcceptedOutcome::Request { .. },
        } => "request pending",
        ContactOperationOutcome::Accepted {
            outcome: ContactAcceptedOutcome::Response { .. },
        } => "respond accepted",
        ContactOperationOutcome::Accepted {
            outcome: ContactAcceptedOutcome::Reject { .. },
        } => "respond rejected",
        ContactOperationOutcome::Accepted { .. } => "contact updated",
        ContactOperationOutcome::Prepared { .. } => "contact awaiting signature",
        ContactOperationOutcome::Failed { .. } => "contact operation failed",
    }
}

#[derive(Clone, Debug, Default)]
struct PaginationState {
    realms_cursor: Option<String>,
    orgs_cursor: Option<String>,
    actors_cursor: Option<String>,
    loading_more: bool,
}

fn realm_member_count_bucket_text(
    bucket: &arkret_models_discovery::RealmMemberCountBucket,
) -> String {
    match bucket {
        arkret_models_discovery::RealmMemberCountBucket::Bucket(label) => match label {
            arkret_models_discovery::RealmMemberCountBucketLabel::OneToTen => "1-10".to_owned(),
            arkret_models_discovery::RealmMemberCountBucketLabel::ElevenToFifty => {
                "11-50".to_owned()
            }
            arkret_models_discovery::RealmMemberCountBucketLabel::FiftyOneToOneHundred => {
                "51-100".to_owned()
            }
            arkret_models_discovery::RealmMemberCountBucketLabel::OneHundredOneToFiveHundred => {
                "101-500".to_owned()
            }
            arkret_models_discovery::RealmMemberCountBucketLabel::FiveHundredOneToTwoThousand => {
                "501-2000".to_owned()
            }
            arkret_models_discovery::RealmMemberCountBucketLabel::TwoThousandPlus => {
                "2000+".to_owned()
            }
        },
        arkret_models_discovery::RealmMemberCountBucket::Exact(count) => count.to_string(),
    }
}

fn realm_tree_node_from_preview(preview: arkret_models_discovery::RealmPreview) -> RealmTreeNode {
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
    if let Some(history_access) = preview.history_access.clone() {
        tags.insert(history_access);
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
        direct_conversation: false,
        parent_space_id: None,
        child_space_ids: Vec::new(),
        kind: RealmTreeNodeKind::Realm,
        realm_id: id,
    }
}

fn organization_preview_value(preview: arkret_models_discovery::OrganizationPreview) -> Value {
    serde_json::to_value(preview).unwrap_or(Value::Null)
}

fn actor_preview_value(preview: arkret_models_discovery::ActorPreview) -> Value {
    serde_json::to_value(preview).unwrap_or(Value::Null)
}

fn actor_preview_identity(value: &Value) -> Option<arkret_wire::ActorId> {
    value
        .get("actor_id")
        .cloned()
        .and_then(|actor| serde_json::from_value(actor).ok())
}

#[component]
pub fn DirectoryPanel(
    selected_realm_id: Signal<String>,
    token: Signal<String>,
    view: Signal<super::AppView>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    // (state_store: F-REMARK-FANOUT-1 — handle resolution prefers the
    // accepted-human ContactRemark.petname over the canonical principal id.)
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
                                value: "all_history_for_current_members".to_owned(),
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
                        history_access: Some("all_history_for_current_members".to_owned()),
                    }
                    span { class: "muted", "·" }
                    crate::components::VisibilityPillRow {
                        discoverability: Some("invite_only".to_owned()),
                        join_rule: Some("restricted".to_owned()),
                        history_access: Some("since_join".to_owned()),
                    }
                }
            }

            div { class: "event", "data-testid": "directory-surface-map",
                div { class: "event-head",
                    span { "Search scope" }
                    span { "entity discovery only" }
                }
                div { class: "muted",
                    "Search stays focused on Realms, organizations, actors, and handles. The old directory shortcut has been folded into the global search entrypoint."
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
                        placeholder: "Requester ActorId (JSON)",
                        oninput: move |event: FormEvent| contact_requester_did.set(event.value())
                    }
                    div {
                        class: "muted",
                        "data-testid": "contact-operation-status",
                        "{contact_state}"
                    }
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
                                        Ok(contact) => contact_state
                                            .set(contact_operation_status(&contact).to_owned()),
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
                                        Ok(()) => contact_state.set("respond accepted".to_owned()),
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
                                        Ok(()) => contact_state.set("respond rejected".to_owned()),
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
                                                .map(|contact| {
                                                    format!(
                                                        "{} {}",
                                                        crate::models::contact_peer_id(contact),
                                                        crate::models::contact_state_wire(contact.state)
                                                    )
                                                })
                                                .collect::<Vec<_>>()
                                                .join(", ");
                                            contact_state.set(format!(
                                                "contacts {} {}",
                                                result.contacts.len(),
                                                summary
                                            ));
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
                            DirectoryTab::Realms => "Search realms",
                            DirectoryTab::Organizations => "Search organizations",
                            DirectoryTab::Actors => "Search actors",
                            DirectoryTab::Handles => "Resolve handle",
                        },
                        placeholder: match active_tab() {
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
                                                                .map(actor_preview_value)
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
                                                                    .map(actor_preview_value)
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
                        let org_id = value_str(&org, "organization_id", "-");
                        let org_name = value_str_any(&org, &["display_name", "name"], "unknown");
                        let org_description = value_str(&org, "description", "");
                        let org_handle = value_str(&org, "handle", "");
                        let discoverability = value_str(&org, "discoverability", "unknown");
                        let profile_visibility = value_str(&org, "profile_visibility", "unknown");
                        let directory_ids = value_vec(&org, "directory_ids");
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
                        let org_id_label = short_protocol_id(&org_id);
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
                                div { class: "event-head",
                                    span { "organization" }
                                    span { title: "{org_id}", "{org_id_label}" }
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
                                    span { class: "badge badge-success", "{directory_ids.len()} directory service(s)" }
                                    span { class: "badge badge-warning", "{proof_count} proof(s)" }
                                }
                                if !directory_ids.is_empty() {
                                    div { class: "muted", "Directory services: {directory_ids.join(\", \")}" }
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
                for (actor, actor_id) in actor_results().into_iter().filter_map(|actor| {
                    actor_preview_identity(&actor).map(|identity| (actor, identity.to_string()))
                }) {
                    div {
                        // Preserve the Station in identity keys and action targets.
                        key: "{actor_id}",
                        class: "event",
                        "data-testid": "actor-result",
                        div { class: "event-head",
                            span { "actor" }
                            {
                                let actor_id_label =
                                    actor_display_label(&state_store.read(), &actor_id);
                                rsx! {
                                    span { title: "{actor_id}", "{actor_id_label}" }
                                }
                            }
                        }
                        div { class: "actions", style: "align-items: center; gap: 12px;",
                            // Directory actor avatars use the canonical
                            // authenticated Blob reference from Actor Profile.
                            {
                                let avatar_blob_ref = actor
                                    .get("avatar_blob_ref")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let actor_label = actor
                                    .get("display_name")
                                    .and_then(|v| v.as_str())
                                    .filter(|value| !value.trim().is_empty())
                                    .unwrap_or(actor_id.as_str());
                                rsx! {
                                    crate::components::IdentityAvatar {
                                        seed: actor_id.to_owned(),
                                        alt_text: format!("Avatar for {actor_label}"),
                                        blob_ref: Some(avatar_blob_ref.to_owned()),
                                        class: "avatar-img sm".to_owned(),
                                        test_id: Some("directory-actor-avatar".to_owned()),
                                    }
                                }
                            }
                            div {
                                div { class: "entity-title", "{actor.get(\"handle\").and_then(|v| v.as_str()).unwrap_or(\"unknown\")}" }
                                div { class: "muted", "{actor.get(\"display_name\").and_then(|v| v.as_str()).unwrap_or(\"\")}" }
                            }
                            // G3.Y3 — directory-side `block-actor-button`.
                            // Navigates to the blocklist settings page
                            // with the target stable identity id prefilled via the
                            // local state store, so the cotest
                            // `personal-blocklist` scenario can pick a
                            // peer from search results and block them
                            // without typing the id by hand.
                            //
                            // TODO(G3.Y3-followup): replace the route-only
                            // hop with an in-place block confirmation overlay
                            // backed by the canonical account-data PUT for
                            // `ak.account.blocklist`; today the click is just
                            // a shortcut into `/settings/blocklist`.
                            {
                                rsx! {
                                    Link {
                                        class: "secondary",
                                        "data-testid": "block-actor-button",
                                        "data-actor-id": "{actor_id}",
                                        to: Route::SettingsSection {
                                            section: "blocklist".to_owned(),
                                            filter: String::new(),
                                        },
                                        "Block"
                                    }
                                }
                            }
                            {
                                let actor_id_label =
                                    actor_display_label(&state_store.read(), &actor_id);
                                rsx! {
                                    div {
                                        class: "muted",
                                        "data-testid": "actor-result-id",
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
                                                            .map(actor_preview_value),
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
                        // (if any) for the resolved stable principal id, with
                        // the canonical id kept verbatim in `title`.
                        let resolved_display =
                            actor_display_label(&state_store.read(), resolved.account_id.principal_id.as_str());
                        let resolved_principal_id_attr = resolved.account_id.principal_id.clone();
                        rsx! {
                            div { class: "event", "data-testid": "handle-result",
                                div { class: "event-head",
                                    span { "Resolved" }
                                    span { "{resolved.handle}" }
                                }
                                div { class: "entity-title", title: "{resolved_principal_id_attr}", "{resolved_display}" }
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
/// A bare `verified_badge` / `verified` bool is deliberately NOT honored on its
/// own: it cannot distinguish a declared hint from a verified relationship.
/// Field names align with the forthcoming teabay / soland projection
/// (TBY-ORG-02): a `verified_relationships` array of
/// `{relationship, status, expires_at}` objects.
fn verified_org_relationships(org: &Value) -> Vec<String> {
    // A stale / divergent projection is never authoritative enough to badge.
    if value_bool_any(org, &["stale"]) || value_bool_any(org, &["divergent"]) {
        return Vec::new();
    }

    let now = crate::clock::now_timestamp();
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
            if let Some(expires_at) = entry.get("expires_at").and_then(|value| value.as_str())
                && !expires_at.is_empty()
                && expires_at <= now.as_str()
            {
                continue;
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
    use arkret_sdk::contact_operations::{
        ContactAcceptedOutcome, ContactOperationOutcome, RequestAcceptanceReceipt,
        RequestAcceptanceReceiptCore,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn accepted_contact_request_renders_pending_without_debug_receipt() {
        let core: RequestAcceptanceReceiptCore = serde_json::from_value(json!({
            "holder": {"kind": "human", "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "peer": {"kind": "human", "account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "slot_version": 1,
            "request_event_ref": "ak:event:AffHQLS6LHEezp3Czebm6JrWc0UdDt4xsoYf_l2OnrHI",
            "source_checkpoint": "sha256:04597468570b5436fdcfe18337daf5bbf2515b148e37dc629cdeea1e63057e85",
            "accepted_at": "2026-08-14T00:00:00.000Z",
            "issuer_id": "ak:did_core:web:service.example"
        }))
        .unwrap();
        let receipt: RequestAcceptanceReceipt = serde_json::from_value(json!({
            "core": core,
            "receipt_digest": "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
            "signature": {
                "verification_method": "did:web:service.example#receipt",
                "created_at": "2026-08-14T00:00:00.000Z",
                "jws": "fixture"
            }
        }))
        .unwrap();
        let outcome = ContactOperationOutcome::Accepted {
            outcome: ContactAcceptedOutcome::Request {
                operation_id: arkret_sdk::ProtocolOperationId::new(
                    "ak:operation:contact.request.01904100-0000-7000-8000-57d7d85564c5",
                )
                .unwrap(),
                request_acceptance_receipt: receipt,
            },
        };

        assert_eq!(contact_operation_status(&outcome), "request pending");
    }

    #[test]
    fn actor_preview_preserves_station_bound_identity_for_rendering() {
        let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
            crate::mls_api_helpers::principal_core_id("did:web:station-a.example").unwrap(),
        ));
        let preview = arkret_models_discovery::ActorPreview {
            actor_id: actor_id.clone(),
            handle: Some("alice:example.com".to_owned()),
            display_name: Some("Alice".to_owned()),
            organization_id: None,
            avatar_blob_ref: None,
            as_of: chrono::Utc::now(),
            source_refs: Vec::new(),
            policy_revision: "test".to_owned(),
            stale: None,
            divergent: None,
        };

        let rendered = actor_preview_value(preview);
        assert_eq!(actor_preview_identity(&rendered), Some(actor_id.clone()));
        assert!(rendered.get("did").is_none());
        let other_station_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id.signing_principal_id().clone(),
            crate::mls_api_helpers::principal_core_id("did:web:station-b.example").unwrap(),
        ));
        assert_ne!(actor_id.to_string(), other_station_actor.to_string());
        assert_ne!(
            actor_preview_identity(&json!({"actor_id": other_station_actor})),
            Some(actor_id)
        );
        assert!(
            actor_preview_identity(&json!({"actor_id": "ak:did_core:web:alice.example"})).is_none()
        );
    }

    #[test]
    fn declared_only_org_gets_no_verified_badge() {
        // YGN-ORG-04 acceptance: a declared-only Realm/organization with no
        // proof-backed relationship array shows no verified badge.
        let org = json!({
            "organization_id": "ak:did_core:web:hint.example",
            "display_name": "Hinted Org",
            // A bare bool is intentionally ignored on its own.
            "verified_badge": true,
        });
        assert!(verified_org_relationships(&org).is_empty());
    }

    #[test]
    fn active_relationships_are_badged() {
        let org = json!({
            "organization_id": "ak:did_core:web:acme.example",
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
                { "relationship": "governance", "status": "active", "expires_at": "2000-01-01T00:00:00.000Z" },
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
                { "relationship": "directory_certifier", "status": "active", "expires_at": "9999-01-01T00:00:00.000Z" },
            ],
        });
        assert_eq!(
            verified_org_relationships(&org),
            vec!["directory_certifier".to_owned()]
        );
    }
}
