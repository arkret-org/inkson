use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::json;

use crate::{models::SpacePreview, routes::Route, views::helpers::authed_api};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupSection {
    Overview,
    Spaces,
}

impl SetupSection {
    fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or_default() {
            "spaces" => Self::Spaces,
            _ => Self::Overview,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Overview => "",
            Self::Spaces => "spaces",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Overview => "Workspace Setup",
            Self::Spaces => "Space Setup",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Self::Overview => "where bootstrap tasks live now",
            Self::Spaces => "create / policy / seed members",
        }
    }
}

#[component]
pub fn SetupPanel(
    base_url: String,
    token: Signal<String>,
    mut selected_space: Signal<String>,
    mut spaces: Signal<Vec<SpacePreview>>,
    mut status: Signal<String>,
    section: Option<String>,
) -> Element {
    let active_section = SetupSection::from_slug(section.as_deref());
    let has_session = !token().trim().is_empty();

    let mut member_did = use_signal(|| "did:web:bob.example".to_owned());
    let mut space_title = use_signal(|| "Setup Flow Space".to_owned());
    let mut space_summary = use_signal(|| "Created from yougen workspace setup".to_owned());
    let mut space_discoverability = use_signal(|| "invite_only".to_owned());
    let mut space_policy_join_rule = use_signal(|| "restricted".to_owned());
    let mut space_policy_history_visibility = use_signal(|| "invited".to_owned());
    let mut space_state = use_signal(|| "No space setup operation yet".to_owned());
    let selected_space_id = selected_space();

    rsx! {
        div { class: "timeline", "data-testid": "setup-panel",
            div { class: "event", "data-testid": "workspace-setup-banner",
                div { class: "event-head",
                    span { "{active_section.title()}" }
                    span { "{active_section.subtitle()}" }
                }
                div { class: "muted",
                    "Setup is no longer a protocol-tool dump. Account bootstrap now lives under Onboarding, people and relationship tools live under Directory, and canonical message persistence belongs inside a Space timeline."
                }
                div { class: "actions",
                    Link {
                        class: if active_section == SetupSection::Overview { "primary" } else { "secondary" },
                        to: Route::Setup,
                        "Setup Map"
                    }
                    Link {
                        class: if active_section == SetupSection::Spaces { "primary" } else { "secondary" },
                        to: Route::SetupSection { section: SetupSection::Spaces.slug().to_owned() },
                        "Space Setup"
                    }
                    Link { class: "secondary", to: Route::Onboarding, "Identity Setup" }
                    Link { class: "secondary", to: Route::Directory, "People & Directory" }
                    Link { class: "secondary", to: Route::Audit, "Protocol Audit" }
                }
            }

            if active_section == SetupSection::Overview {
                div { class: "event", "data-testid": "workspace-setup-map",
                    div { class: "event-head",
                        span { "Setup Surfaces" }
                        span { "single-purpose entrypoints" }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Space Setup" }
                            span { "create / seed / policy" }
                            div { class: "muted",
                                "Use this when you need a new Space, want to seed initial members, or need to set join/history defaults before collaboration starts."
                            }
                            Link {
                                class: "secondary",
                                to: Route::SetupSection { section: SetupSection::Spaces.slug().to_owned() },
                                "Open Space Setup"
                            }
                        }
                        div { class: "metric",
                            strong { "Onboarding" }
                            span { "identity bootstrap" }
                            div { class: "muted",
                                "Account registration, DID method choice, handle binding, device setup, and recovery guidance now live in the onboarding flow."
                            }
                            Link { class: "secondary", to: Route::Onboarding, "Open Onboarding" }
                        }
                        div { class: "metric",
                            strong { "Directory" }
                            span { "actors / handles / contacts" }
                            div { class: "muted",
                                "Find spaces, organizations, actors, and handles there. Relationship operations no longer share the Space bootstrap surface."
                            }
                            Link { class: "secondary", to: Route::Directory, "Open Directory" }
                        }
                        div { class: "metric",
                            strong { "Space timeline" }
                            span { "canonical message writes" }
                            div { class: "muted",
                                "Canonical message persistence happens from the current Space timeline, so write state stays inside the active Space context instead of a global setup page."
                            }
                            if selected_space_id.trim().is_empty() {
                                Link { class: "secondary", to: Route::Timeline, "Open Timeline" }
                            } else {
                                Link {
                                    class: "secondary",
                                    to: Route::Space { space_id: selected_space_id.clone() },
                                    "Open Current Space"
                                }
                            }
                        }
                    }
                }

                div { class: "event", "data-testid": "workspace-setup-checklist",
                    div { class: "event-head",
                        span { "What Moved" }
                        span { "IA cleanup" }
                    }
                    div { class: "muted",
                        "The old setup dump mixed account state, contacts, space lifecycle, and sync drills. Those responsibilities are now split by object boundary."
                    }
                    div { class: "actions",
                        span { class: "badge", "Onboarding = identity bootstrap" }
                        span { class: "badge", "Directory = people / handles" }
                        span { class: "badge", "Spaces = collaboration context" }
                        span { class: "badge", "Audit = protocol diagnostics" }
                    }
                }
            }

            if active_section == SetupSection::Spaces {
                div { class: "event", "data-testid": "space-setup-guide",
                    div { class: "event-head",
                        span { "Space Setup" }
                        span { "bootstrap only" }
                    }
                    div { class: "muted",
                        "This surface is for bringing a Space into existence and setting its initial policy. Ongoing collaboration, messaging, board work, and document work should happen after you enter the Space itself."
                    }
                    if !selected_space_id.trim().is_empty() {
                        div { class: "actions",
                            Link {
                                class: "primary",
                                to: Route::Space { space_id: selected_space_id.clone() },
                                "Open Current Space"
                            }
                            Link {
                                class: "secondary",
                                to: Route::SpaceAdmin { space_id: selected_space_id.clone() },
                                "Open Space Admin"
                            }
                            span { class: "muted mono", "{selected_space_id}" }
                        }
                    }
                }

                div { class: "event", "data-testid": "space-lifecycle-flow",
                    div { class: "event-head",
                        span { "Space lifecycle" }
                        span { "create / policy / member seed" }
                    }
                    div { class: "workflow-form",
                        input {
                            "data-testid": "space-title-input",
                            value: "{space_title}",
                            oninput: move |event| space_title.set(event.value())
                        }
                        input {
                            "data-testid": "space-summary-input",
                            value: "{space_summary}",
                            oninput: move |event| space_summary.set(event.value())
                        }
                        input {
                            "data-testid": "space-discoverability-input",
                            value: "{space_discoverability}",
                            oninput: move |event| space_discoverability.set(event.value())
                        }
                        input {
                            "data-testid": "member-did-input",
                            value: "{member_did}",
                            oninput: move |event| member_did.set(event.value())
                        }
                        input {
                            "data-testid": "selected-space-id-input",
                            value: "{selected_space_id}",
                            oninput: move |event| selected_space.set(event.value())
                        }
                        input {
                            "data-testid": "space-policy-join-rule-input",
                            value: "{space_policy_join_rule}",
                            oninput: move |event| space_policy_join_rule.set(event.value())
                        }
                        input {
                            "data-testid": "space-policy-history-visibility-input",
                            value: "{space_policy_history_visibility}",
                            oninput: move |event| space_policy_history_visibility.set(event.value())
                        }
                        div { class: "muted", "{space_state}" }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "create-space-button",
                                disabled: !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let base = base.clone();
                                        let title = space_title();
                                        let summary = space_summary();
                                        let discoverability = space_discoverability();
                                        let invitee = member_did();
                                        spawn(async move {
                                            match authed_api(&base, api_token) {
                                                Ok(api) => match api.create_space(&title, Some(&summary), discoverability == "public", vec![invitee]).await {
                                                    Ok(space) => {
                                                        selected_space.set(space.space_id.clone());
                                                        spaces.write().retain(|preview| preview.space_id != space.space_id);
                                                        spaces.write().push(SpacePreview {
                                                            space_id: space.space_id.clone(),
                                                            name: title.clone(),
                                                            description: Some(summary.clone()),
                                                            tags: Default::default(),
                                                            public: discoverability == "public",
                                                            category: Some("collaboration".to_owned()),
                                                        });
                                                        let message = format!(
                                                            "created {} with {} member(s)",
                                                            space.space_id,
                                                            space.members.len()
                                                        );
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                    Err(error) => {
                                                        let message = format!("create failed: {error}");
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => {
                                                    let message = format!("invalid server URL: {error}");
                                                    space_state.set(message.clone());
                                                    status.set(message);
                                                }
                                            }
                                        });
                                    }
                                },
                                "Create Space"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "update-space-button",
                                disabled: !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let base = base.clone();
                                        let space = selected_space();
                                        let title = space_title();
                                        let summary = space_summary();
                                        let discoverability = space_discoverability();
                                        spawn(async move {
                                            match authed_api(&base, api_token) {
                                                Ok(api) => match api.update_space(
                                                    &space,
                                                    json!({
                                                        "title": title,
                                                        "summary": summary,
                                                        "discoverability": discoverability,
                                                    }),
                                                ).await {
                                                    Ok(result) => {
                                                        let message = format!("updated {}", result.space_id);
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                    Err(error) => {
                                                        let message = format!("update failed: {error}");
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => {
                                                    let message = format!("invalid server URL: {error}");
                                                    space_state.set(message.clone());
                                                    status.set(message);
                                                }
                                            }
                                        });
                                    }
                                },
                                "Update Space"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "set-space-policy-button",
                                disabled: !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let base = base.clone();
                                        let space = selected_space();
                                        let join_rule = space_policy_join_rule();
                                        let history_visibility = space_policy_history_visibility();
                                        spawn(async move {
                                            match authed_api(&base, api_token) {
                                                Ok(api) => match api.set_space_policy(&space, &join_rule, &history_visibility).await {
                                                    Ok(result) => {
                                                        let message = format!(
                                                            "policy {} {}",
                                                            result.join_rule,
                                                            result.history_visibility
                                                        );
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                    Err(error) => {
                                                        let message = format!("policy failed: {error}");
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => {
                                                    let message = format!("invalid server URL: {error}");
                                                    space_state.set(message.clone());
                                                    status.set(message);
                                                }
                                            }
                                        });
                                    }
                                },
                                "Set Policy"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "add-member-button",
                                disabled: !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let base = base.clone();
                                        let space = selected_space();
                                        let member = member_did();
                                        spawn(async move {
                                            match authed_api(&base, api_token) {
                                                Ok(api) => match api.add_space_member(&space, &member).await {
                                                    Ok(result) => {
                                                        let message = format!("members {}", result.members.len());
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                    Err(error) => {
                                                        let message = format!("add member failed: {error}");
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => {
                                                    let message = format!("invalid server URL: {error}");
                                                    space_state.set(message.clone());
                                                    status.set(message);
                                                }
                                            }
                                        });
                                    }
                                },
                                "Add Member"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "remove-member-button",
                                disabled: !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let base = base.clone();
                                        let space = selected_space();
                                        let member = member_did();
                                        spawn(async move {
                                            match authed_api(&base, api_token) {
                                                Ok(api) => match api.remove_space_member(&space, &member).await {
                                                    Ok(result) => {
                                                        let message = format!("removed; members {}", result.members.len());
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                    Err(error) => {
                                                        let message = format!("remove member failed: {error}");
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => {
                                                    let message = format!("invalid server URL: {error}");
                                                    space_state.set(message.clone());
                                                    status.set(message);
                                                }
                                            }
                                        });
                                    }
                                },
                                "Remove Member"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "delete-space-button",
                                disabled: !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let base = base.clone();
                                        let space = selected_space();
                                        spawn(async move {
                                            match authed_api(&base, api_token) {
                                                Ok(api) => match api.delete_space(&space).await {
                                                    Ok(result) => {
                                                        spaces.write().retain(|preview| preview.space_id != result.space_id);
                                                        let message = format!("deleted {}", result.deleted);
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                    Err(error) => {
                                                        let message = format!("delete failed: {error}");
                                                        space_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => {
                                                    let message = format!("invalid server URL: {error}");
                                                    space_state.set(message.clone());
                                                    status.set(message);
                                                }
                                            }
                                        });
                                    }
                                },
                                "Delete Space"
                            }
                        }
                    }
                }

                div { class: "event", "data-testid": "space-setup-followup",
                    div { class: "event-head",
                        span { "After Setup" }
                        span { "enter the Space context" }
                    }
                    div { class: "muted",
                        "Once the Space exists, switch into the Space view shell for Timeline, Board, Discussion, Document, and Space Admin. Message persistence no longer lives on this setup page."
                    }
                    div { class: "actions",
                        if selected_space_id.trim().is_empty() {
                            Link { class: "secondary", to: Route::Timeline, "Open global Timeline" }
                        } else {
                            Link {
                                class: "secondary",
                                to: Route::Space { space_id: selected_space_id.clone() },
                                "Open Space Timeline"
                            }
                            Link {
                                class: "secondary",
                                to: Route::SpaceAdmin { space_id: selected_space_id.clone() },
                                "Open Space Admin"
                            }
                        }
                        Link { class: "secondary", to: Route::Audit, "Open Audit" }
                    }
                }
            }
        }
    }
}
