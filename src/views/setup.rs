use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::json;

use crate::{
    components::PermissionPillRow, models::SpacePreview, routes::Route,
    views::helpers::authed_api,
};

const DISCOVERABILITY_OPTIONS: [(&str, &str, &str); 6] = [
    (
        "public",
        "Public",
        "Findable in Search. Existence and join surface can be broadly disclosed.",
    ),
    (
        "listed",
        "Listed",
        "Visible in Search, but still separate from how people join or what history they see.",
    ),
    (
        "restricted",
        "Restricted",
        "Directory presence is limited to principals that already satisfy server-side policy.",
    ),
    (
        "unlisted",
        "Unlisted",
        "Not browseable in Search. Entry depends on a direct link or explicit reference.",
    ),
    (
        "invite_only",
        "Invite only",
        "Existence is disclosed only to specifically invited principals.",
    ),
    (
        "secret",
        "Secret",
        "The Space should not disclose that it exists to unauthorized viewers.",
    ),
];

const JOIN_RULE_OPTIONS: [(&str, &str, &str); 6] = [
    (
        "public",
        "Public",
        "Anyone who can see the Space can join without a separate approval step.",
    ),
    (
        "invite",
        "Invite",
        "Joining requires a member or admin to grant admission explicitly.",
    ),
    (
        "knock",
        "Knock",
        "Applicants can request entry and wait for review.",
    ),
    (
        "restricted",
        "Restricted",
        "Joining depends on policy or claims, even if the Space is discoverable.",
    ),
    (
        "knock_restricted",
        "Knock + restricted",
        "Applicants request entry, then additional eligibility policy is checked.",
    ),
    (
        "closed",
        "Closed",
        "No self-serve admission path. Membership is controlled out of band.",
    ),
];

const HISTORY_VISIBILITY_OPTIONS: [(&str, &str, &str); 5] = [
    (
        "world_readable",
        "World readable",
        "Past history is readable without joining. Use only with intentionally open Spaces.",
    ),
    (
        "shared",
        "Shared",
        "New members can read the pre-join history that is meant to be shared with the whole Space.",
    ),
    (
        "invited",
        "Invited",
        "History is visible only from the point an invite made the principal eligible.",
    ),
    (
        "joined",
        "Joined",
        "History starts when the principal actually becomes a member.",
    ),
    (
        "restricted",
        "Restricted",
        "Past history stays tightly scoped; new members see only what policy re-discloses.",
    ),
];

const CREATE_LOCKED_FIELDS: [(&str, &str); 4] = [
    ("security_class", "standard"),
    ("encryption_profile", "mls_rfc9420"),
    ("anchor_profile", "single_did"),
    ("hash_profile", "sha256"),
];

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
            Self::Spaces => "New Space",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Self::Overview => "where bootstrap tasks live now",
            Self::Spaces => "boundary / seed members / bootstrap only",
        }
    }
}

fn discoverability_is_publicish(value: &str) -> bool {
    matches!(value, "public" | "listed")
}

fn parse_seed_members(seed_members: &str, fallback_member: &str) -> Vec<String> {
    let mut members = Vec::new();

    let push_unique = |value: &str, members: &mut Vec<String>| {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !members.iter().any(|existing| existing == trimmed) {
            members.push(trimmed.to_owned());
        }
    };

    for candidate in seed_members.split(|ch: char| matches!(ch, ',' | '\n' | '\r' | '\t' | ';')) {
        push_unique(candidate, &mut members);
    }

    if members.is_empty() {
        push_unique(fallback_member, &mut members);
    }

    members
}

fn policy_combination_hint(
    discoverability: &str,
    join_rule: &str,
    history_visibility: &str,
) -> Option<(&'static str, &'static str, &'static str)> {
    if discoverability == "secret"
        && (join_rule == "public" || history_visibility == "world_readable")
    {
        return Some((
            "error",
            "Combination invalid",
            "A secret Space cannot also advertise public admission or world-readable history.",
        ));
    }

    if discoverability == "invite_only" && join_rule == "public" {
        return Some((
            "warning",
            "Combination is contradictory",
            "Invite-only discovery paired with public join usually means the discovery model is underspecified.",
        ));
    }

    if matches!(discoverability, "invite_only" | "secret")
        && history_visibility == "world_readable"
    {
        return Some((
            "warning",
            "History leaks more than existence",
            "If history is world-readable, the Space behaves more openly than its discovery setting suggests.",
        ));
    }

    None
}

fn sync_space_preview(
    previews: &mut Vec<SpacePreview>,
    space_id: String,
    name: String,
    summary: String,
    public: bool,
) {
    previews.retain(|preview| preview.space_id != space_id);
    previews.push(SpacePreview {
        space_id,
        name,
        description: Some(summary),
        tags: Default::default(),
        public,
        category: Some("collaboration".to_owned()),
    });
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
    let mut seed_members = use_signal(|| "did:web:bob.example".to_owned());
    let mut space_title = use_signal(|| "Setup Flow Space".to_owned());
    let mut space_summary = use_signal(|| "Created from yougen workspace setup".to_owned());
    let mut space_discoverability = use_signal(|| "listed".to_owned());
    let mut space_policy_join_rule = use_signal(|| "invite".to_owned());
    let mut space_policy_history_visibility = use_signal(|| "shared".to_owned());
    let mut space_state = use_signal(|| "No space bootstrap operation yet".to_owned());

    let selected_space_id = selected_space();
    let title_value = space_title();
    let summary_value = space_summary();
    let discoverability_value = space_discoverability();
    let join_rule_value = space_policy_join_rule();
    let history_visibility_value = space_policy_history_visibility();
    let member_did_value = member_did();
    let seed_members_value = seed_members();
    let space_state_value = space_state();
    let parsed_seed_members = parse_seed_members(&seed_members_value, &member_did_value);
    let seed_member_count = parsed_seed_members.len();
    let has_selected_space = !selected_space_id.trim().is_empty();
    let can_create_space = has_session && !title_value.trim().is_empty();
    let can_mutate_selected_space = has_session && has_selected_space;
    let current_visibility_hint = policy_combination_hint(
        &discoverability_value,
        &join_rule_value,
        &history_visibility_value,
    );

    rsx! {
        div { class: "timeline", "data-testid": "setup-panel",
            div { class: "event", "data-testid": "workspace-setup-banner",
                div { class: "event-head",
                    span { "{active_section.title()}" }
                    span { "{active_section.subtitle()}" }
                }
                div { class: "muted",
                    "Setup is no longer a protocol-tool dump. Identity bootstrap lives under Onboarding, people and discovery live under Search, and ongoing collaboration belongs inside a Space shell."
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
                        "New Space"
                    }
                    Link { class: "secondary", to: Route::Onboarding, "Onboarding" }
                    Link { class: "secondary", to: Route::Directory, "Search" }
                    Link { class: "secondary", to: Route::Settings, "Settings" }
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
                            strong { "New Space" }
                            span { "boundary-first bootstrap" }
                            div { class: "muted",
                                "Create a Space, define the three boundary axes, and seed the first members before collaboration starts."
                            }
                            Link {
                                class: "secondary",
                                to: Route::SetupSection { section: SetupSection::Spaces.slug().to_owned() },
                                "Open New Space"
                            }
                        }
                        div { class: "metric",
                            strong { "Onboarding" }
                            span { "identity bootstrap" }
                            div { class: "muted",
                                "Account registration, DID method choice, device setup, and recovery guidance now live in the onboarding flow."
                            }
                            Link { class: "secondary", to: Route::Onboarding, "Open Onboarding" }
                        }
                        div { class: "metric",
                            strong { "Search" }
                            span { "actors / handles / spaces" }
                            div { class: "muted",
                                "Find spaces, organizations, and people there. Relationship operations no longer share the Space bootstrap surface."
                            }
                            Link { class: "secondary", to: Route::Directory, "Open Search" }
                        }
                        div { class: "metric",
                            strong { "Space timeline" }
                            span { "after bootstrap" }
                            div { class: "muted",
                                "Once the Space exists, move into the Space shell for timeline, board, discussion, document, and admin work."
                            }
                            if has_selected_space {
                                Link {
                                    class: "secondary",
                                    to: Route::Space { space_id: selected_space_id.clone() },
                                    "Open Current Space"
                                }
                            } else {
                                Link { class: "secondary", to: Route::Timeline, "Open Timeline" }
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
                        "The old setup dump mixed account state, contacts, space lifecycle, and sync drills. Those responsibilities are now split by object boundary and ongoing context."
                    }
                    div { class: "actions",
                        span { class: "badge", "Onboarding = identity bootstrap" }
                        span { class: "badge", "Search = discovery and people" }
                        span { class: "badge", "New Space = boundary bootstrap" }
                        span { class: "badge", "Settings = recovery and operations" }
                    }
                }
            }

            if active_section == SetupSection::Spaces {
                div { class: "setup-shell", "data-testid": "space-lifecycle-flow",
                    div { class: "setup-column",
                        div { class: "event settings-content-hero", "data-testid": "space-setup-guide",
                            div { class: "event-head",
                                span { "New Space" }
                                span { "bootstrap only" }
                            }
                            h2 { class: "settings-content-title", "Create a Space from boundary first, not from a protocol field dump." }
                            div { class: "muted",
                                "The spec treats discoverability, join rule, and history visibility as three independent axes. This page edits those axes separately, then applies the result as a coherent bootstrap."
                            }
                            PermissionPillRow {
                                discoverability: Some(discoverability_value.clone()),
                                join_rule: Some(join_rule_value.clone()),
                                history_visibility: Some(history_visibility_value.clone()),
                            }
                        }

                        div { class: "event",
                            div { class: "event-head",
                                span { "Basics" }
                                span { "name / summary" }
                            }
                            div { class: "workflow-form setup-form-grid",
                                div { class: "setup-field" ,
                                    label { "Space title" }
                                    input {
                                        "data-testid": "space-title-input",
                                        value: "{title_value}",
                                        placeholder: "Engineering, Research, Design system...",
                                        oninput: move |event| space_title.set(event.value())
                                    }
                                    div { class: "muted", "Human-facing title shown in Space lists and headers." }
                                }
                                div { class: "setup-field setup-field-span-2",
                                    label { "Summary" }
                                    textarea {
                                        "data-testid": "space-summary-input",
                                        value: "{summary_value}",
                                        rows: "3",
                                        placeholder: "What this Space is for, who it serves, and what should happen here.",
                                        oninput: move |event| space_summary.set(event.value())
                                    }
                                    div { class: "muted", "Short, legible intent statement. This is not the place for policy internals." }
                                }
                            }
                        }

                        div { class: "event",
                            div { class: "event-head",
                                span { "Boundary" }
                                span { "three independent axes" }
                            }
                            div { class: "muted",
                                "The UI must not collapse these dimensions into a single privacy preset. Discovery, admission, and history are separate policy questions."
                            }
                            div { class: "setup-axis-grid",
                                div { class: "metric directory-axis-card",
                                    strong { "Discoverability" }
                                    div { class: "workflow-form setup-field",
                                        label { "Who can discover that this Space exists?" }
                                        select {
                                            "data-testid": "space-discoverability-input",
                                            value: "{discoverability_value}",
                                            onchange: move |event| space_discoverability.set(event.value()),
                                            for (option_value, label, _) in DISCOVERABILITY_OPTIONS {
                                                option {
                                                    value: "{option_value}",
                                                    selected: discoverability_value == option_value,
                                                    "{label}"
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            "{DISCOVERABILITY_OPTIONS.iter().find(|(value, _, _)| *value == discoverability_value).map(|(_, _, hint)| *hint).unwrap_or(\"Discovery posture is not set.\")}"
                                        }
                                    }
                                }
                                div { class: "metric directory-axis-card",
                                    strong { "Join rule" }
                                    div { class: "workflow-form setup-field",
                                        label { "How does a principal become a member?" }
                                        select {
                                            "data-testid": "space-policy-join-rule-input",
                                            value: "{join_rule_value}",
                                            onchange: move |event| space_policy_join_rule.set(event.value()),
                                            for (option_value, label, _) in JOIN_RULE_OPTIONS {
                                                option {
                                                    value: "{option_value}",
                                                    selected: join_rule_value == option_value,
                                                    "{label}"
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            "{JOIN_RULE_OPTIONS.iter().find(|(value, _, _)| *value == join_rule_value).map(|(_, _, hint)| *hint).unwrap_or(\"Join path is not set.\")}"
                                        }
                                    }
                                }
                                div { class: "metric directory-axis-card",
                                    strong { "History visibility" }
                                    div { class: "workflow-form setup-field",
                                        label { "What history can new members read?" }
                                        select {
                                            "data-testid": "space-policy-history-visibility-input",
                                            value: "{history_visibility_value}",
                                            onchange: move |event| space_policy_history_visibility.set(event.value()),
                                            for (option_value, label, _) in HISTORY_VISIBILITY_OPTIONS {
                                                option {
                                                    value: "{option_value}",
                                                    selected: history_visibility_value == option_value,
                                                    "{label}"
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            "{HISTORY_VISIBILITY_OPTIONS.iter().find(|(value, _, _)| *value == history_visibility_value).map(|(_, _, hint)| *hint).unwrap_or(\"History scope is not set.\")}"
                                        }
                                    }
                                }
                            }
                        }

                        if let Some((tone, heading, body)) = current_visibility_hint {
                            div { class: if tone == "error" { "event error-banner" } else { "event" },
                                div { class: "event-head",
                                    span { "{heading}" }
                                    span { if tone == "error" { "policy_combination_invalid" } else { "needs review" } }
                                }
                                div { class: "muted", "{body}" }
                            }
                        }

                        div { class: "event",
                            div { class: "event-head",
                                span { "Seed members" }
                                span { "bootstrap membership only" }
                            }
                            div { class: "workflow-form setup-form-grid",
                                div { class: "setup-field setup-field-span-2",
                                    label { "Initial members" }
                                    textarea {
                                        value: "{seed_members_value}",
                                        rows: "4",
                                        placeholder: "did:web:alice.example, did:web:bob.example",
                                        oninput: move |event| seed_members.set(event.value())
                                    }
                                    div { class: "muted", "One DID per line or comma-separated. These are used when the Space is first created." }
                                }
                                div { class: "setup-field" ,
                                    label { "Quick member target" }
                                    input {
                                        "data-testid": "member-did-input",
                                        value: "{member_did_value}",
                                        placeholder: "did:web:member.example",
                                        oninput: move |event| member_did.set(event.value())
                                    }
                                    div { class: "muted", "Used by Add Member and Remove Member after the Space already exists." }
                                }
                                div { class: "setup-field" ,
                                    label { "Seed preview" }
                                    div { class: "setup-chip-wrap",
                                        for member in parsed_seed_members.iter().take(6) {
                                            span { class: "badge blue mono", "{member}" }
                                        }
                                    }
                                    div { class: "muted", "{seed_member_count} principal(s) will be included in the bootstrap request." }
                                }
                            }
                        }
                    }

                    div { class: "setup-column",
                        div { class: "event",
                            div { class: "event-head",
                                span { "Bootstrap summary" }
                                span { "current draft" }
                            }
                            div { class: "setup-summary-list",
                                div { class: "setup-summary-row",
                                    strong { "Draft title" }
                                    span { if title_value.trim().is_empty() { "Untitled Space" } else { "{title_value}" } }
                                }
                                div { class: "setup-summary-row",
                                    strong { "Selected Space" }
                                    span { class: "mono", "data-testid": "selected-space-id",
                                        if has_selected_space { "{selected_space_id}" } else { "not created yet" }
                                    }
                                }
                                div { class: "setup-summary-row setup-summary-row-stack",
                                    strong { "Policy draft" }
                                    PermissionPillRow {
                                        discoverability: Some(discoverability_value.clone()),
                                        join_rule: Some(join_rule_value.clone()),
                                        history_visibility: Some(history_visibility_value.clone()),
                                    }
                                }
                                div { class: "setup-summary-row setup-summary-row-stack",
                                    strong { "Bootstrap state" }
                                    span { class: "muted", "{space_state_value}" }
                                }
                            }
                        }

                        div { class: "event",
                            div { class: "event-head",
                                span { "Actions" }
                                span { "create / update / policy / members" }
                            }
                            div { class: "workflow-form setup-field",
                                label { "Target space id" }
                                input {
                                    "data-testid": "selected-space-id-input",
                                    value: "{selected_space_id}",
                                    placeholder: "cx:space:...",
                                    oninput: move |event| selected_space.set(event.value())
                                }
                                div { class: "muted", "After creation, this ID is reused for policy changes and member operations." }
                            }
                            div { class: "setup-action-grid",
                                button {
                                    class: "primary",
                                    "data-testid": "create-space-button",
                                    disabled: !can_create_space,
                                    onclick: {
                                        let base = base_url.clone();
                                        move |_| {
                                            let api_token = token();
                                            let base = base.clone();
                                            let title = space_title();
                                            let summary = space_summary();
                                            let discoverability = space_discoverability();
                                            let join_rule = space_policy_join_rule();
                                            let history_visibility = space_policy_history_visibility();
                                            let seed_text = seed_members();
                                            let fallback_member = member_did();
                                            spawn(async move {
                                                let invitees = parse_seed_members(&seed_text, &fallback_member);
                                                let publicish = discoverability_is_publicish(&discoverability);
                                                match authed_api(&base, api_token) {
                                                    Ok(api) => match api.create_space(&title, Some(&summary), publicish, invitees.clone()).await {
                                                        Ok(space) => {
                                                            selected_space.set(space.space_id.clone());
                                                            sync_space_preview(
                                                                &mut spaces.write(),
                                                                space.space_id.clone(),
                                                                title.clone(),
                                                                summary.clone(),
                                                                publicish,
                                                            );

                                                            let mut steps = vec![
                                                                format!("created {}", space.space_id),
                                                                format!("seeded {} member(s)", invitees.len()),
                                                            ];

                                                            match api.update_space(
                                                                &space.space_id,
                                                                json!({
                                                                    "title": title,
                                                                    "summary": summary,
                                                                    "discoverability": discoverability,
                                                                }),
                                                            ).await {
                                                                Ok(_) => steps.push(format!("discoverability {}", discoverability)),
                                                                Err(error) => steps.push(format!("discoverability sync failed: {error}")),
                                                            }

                                                            match api.set_space_policy(
                                                                &space.space_id,
                                                                &join_rule,
                                                                &history_visibility,
                                                            ).await {
                                                                Ok(result) => steps.push(format!(
                                                                    "policy {} / {}",
                                                                    result.join_rule,
                                                                    result.history_visibility
                                                                )),
                                                                Err(error) => steps.push(format!("policy sync failed: {error}")),
                                                            }

                                                            let message = steps.join(" · ");
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
                                    disabled: !can_mutate_selected_space,
                                    onclick: {
                                        let base = base_url.clone();
                                        move |_| {
                                            let api_token = token();
                                            let base = base.clone();
                                            let space = selected_space();
                                            let title = space_title();
                                            let summary = space_summary();
                                            let discoverability = space_discoverability();
                                            let publicish = discoverability_is_publicish(&discoverability);
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
                                                            sync_space_preview(
                                                                &mut spaces.write(),
                                                                result.space_id.clone(),
                                                                title,
                                                                summary,
                                                                publicish,
                                                            );
                                                            let message = format!(
                                                                "updated {} · discoverability {}",
                                                                result.space_id,
                                                                discoverability
                                                            );
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
                                    disabled: !can_mutate_selected_space,
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
                                                                "policy {} / {}",
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
                                    "Apply Policy"
                                }
                                button {
                                    class: "secondary",
                                    "data-testid": "add-member-button",
                                    disabled: !can_mutate_selected_space,
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
                                    disabled: !can_mutate_selected_space,
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
                                    disabled: !can_mutate_selected_space,
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
                                                            selected_space.set(String::new());
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

                        div { class: "event",
                            div { class: "event-head",
                                span { "Create-locked fields" }
                                span { "cannot change later" }
                            }
                            div { class: "setup-summary-list",
                                for (field, value) in CREATE_LOCKED_FIELDS {
                                    div { class: "setup-summary-row",
                                        strong { "{field}" }
                                        span { class: "badge", "{value}" }
                                    }
                                }
                            }
                            div { class: "muted",
                                "These are shown here so New Space creation feels like a policy decision, not an opaque protocol blob."
                            }
                        }
                    }
                }

                div { class: "event", "data-testid": "space-setup-followup",
                    div { class: "event-head",
                        span { "After setup" }
                        span { "enter the Space context" }
                    }
                    div { class: "muted",
                        "Once the Space exists, move into the Space shell for timeline, board, discussion, document, and longer-lived admin work. This page is only for bootstrap."
                    }
                    div { class: "actions",
                        if has_selected_space {
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
                        } else {
                            Link { class: "secondary", to: Route::Timeline, "Open global Timeline" }
                        }
                    }
                }
            }
        }
    }
}
