use dioxus::prelude::*;

#[component]
pub fn AgentIdentity(
    agent_id: String,
    label: String,
    #[props(default)] avatar_blob_ref: Option<String>,
    #[props(default)] is_opening: bool,
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
        span { class: "pill muted xs",
            if is_opening {
                {crate::i18n::tr("app.sidebar.opening")}
            } else {
                {crate::i18n::tr("app.sidebar.agent_badge")}
            }
        }
    }
}
