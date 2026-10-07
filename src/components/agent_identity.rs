use dioxus::prelude::*;

#[component]
pub fn AgentIdentity(
    agent_id: String,
    label: String,
    #[props(default)] avatar_blob_ref: Option<String>,
    #[props(default)] is_opening: bool,
    #[props(default)] interaction_mode: Option<arkret_sdk::AgentInteractionMode>,
    #[props(default)] label_test_id: Option<String>,
) -> Element {
    rsx! {
        span { class: "sidebar-nav-icon contact-sidebar-agent-avatar",
            super::IdentityAvatar {
                seed: agent_id,
                alt_text: label.clone(),
                blob_ref: avatar_blob_ref,
                class: "avatar-img".to_owned(),
            }
        }
        span { class: "grow truncate", "data-testid": label_test_id, "{label}" }
        span { class: match interaction_mode {
            Some(arkret_sdk::AgentInteractionMode::Public) => "pill xs agent-mode-badge is-public",
            Some(arkret_sdk::AgentInteractionMode::Private) => "pill xs agent-mode-badge is-private",
            None => "pill muted xs",
        },
            if is_opening {
                {crate::i18n::tr("app.sidebar.opening")}
            } else {
                {crate::i18n::tr(match interaction_mode {
                    Some(arkret_sdk::AgentInteractionMode::Public) => "app.sidebar.public_agent_badge",
                    Some(arkret_sdk::AgentInteractionMode::Private) => "app.sidebar.private_agent_badge",
                    None => "app.sidebar.agent_badge",
                })}
            }
        }
    }
}
