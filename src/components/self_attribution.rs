use dioxus::prelude::*;

#[component]
pub fn SelfAttributionBadge(class: Option<String>, test_id: Option<String>) -> Element {
    let class_name = match class {
        Some(extra) if !extra.trim().is_empty() => {
            format!("badge self-attribution-badge {}", extra.trim())
        }
        _ => "badge self-attribution-badge".to_owned(),
    };
    let test_id = test_id.unwrap_or_else(|| "self-attribution-badge".to_owned());

    rsx! {
        span {
            class: "{class_name}",
            "data-testid": "{test_id}",
            title: "This is your account",
            "ME"
        }
    }
}

/// Shared actor label used by member lists, mention suggestions, and compact
/// attribution surfaces. Keeping the self and agent markers here prevents
/// each feature surface from inventing a slightly different identity row.
#[component]
pub fn ActorIdentityLabel(
    label: String,
    title: Option<String>,
    class: Option<String>,
    test_id: Option<String>,
    self_badge_test_id: Option<String>,
    agent_badge_test_id: Option<String>,
    #[props(default)] is_self: bool,
    agent_slug: Option<String>,
    agent_selector: Option<String>,
) -> Element {
    let class_name = match class {
        Some(extra) if !extra.trim().is_empty() => {
            format!("actor-identity-label {}", extra.trim())
        }
        _ => "actor-identity-label".to_owned(),
    };
    let title = title.unwrap_or_else(|| label.clone());
    let test_id = test_id.unwrap_or_else(|| "actor".to_owned());
    let identity_test_id = format!("{test_id}-identity");
    let self_badge_test_id = self_badge_test_id.unwrap_or_else(|| format!("{test_id}-self-badge"));
    let agent_badge_test_id =
        agent_badge_test_id.unwrap_or_else(|| format!("{test_id}-agent-badge"));
    let agent_slug = agent_slug.filter(|slug| !slug.trim().is_empty());
    let agent_selector = agent_selector.filter(|selector| !selector.trim().is_empty());

    rsx! {
        span {
            class: "{class_name}",
            "data-testid": "{identity_test_id}",
            "data-actor-kind": if agent_slug.is_some() { "agent" } else { "user" },
            title: "{title}",
            span { class: "actor-identity-primary", "{label}" }
            if is_self {
                SelfAttributionBadge {
                    class: Some("actor-identity-self-badge".to_owned()),
                    test_id: Some(self_badge_test_id),
                }
            }
            if agent_slug.is_some() {
                span {
                    class: "badge member-badge member-badge-agent actor-identity-agent-badge",
                    "data-testid": "{agent_badge_test_id}",
                    title: "Personal agent",
                    "Agent"
                }
            }
            if let Some(selector) = agent_selector {
                span {
                    class: "actor-identity-selector",
                    "data-testid": "{test_id}-agent-selector",
                    "@{selector}"
                }
            }
        }
    }
}
