use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::widgets::{line, paragraph};
use crate::presentation::{InksonContext, View};
#[derive(Clone)]
pub struct AgentIdentityProps {
    pub agent_id: String,
    pub label: String,
    pub avatar_blob_ref: Option<String>,
    pub is_opening: bool,
    pub interaction_mode: Option<arkret_sdk::AgentInteractionMode>,
    pub label_test_id: Option<String>,
}
pub fn agent_identity(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: AgentIdentityProps,
) -> View {
    let class = match props.interaction_mode {
        Some(arkret_sdk::AgentInteractionMode::Public) => "pill xs agent-mode-badge is-public",
        Some(arkret_sdk::AgentInteractionMode::Private) => "pill xs agent-mode-badge is-private",
        None => "pill muted xs",
    };
    let key = if props.is_opening {
        "app.sidebar.opening"
    } else {
        match props.interaction_mode {
            Some(arkret_sdk::AgentInteractionMode::Public) => "app.sidebar.public_agent_badge",
            Some(arkret_sdk::AgentInteractionMode::Private) => "app.sidebar.private_agent_badge",
            None => "app.sidebar.agent_badge",
        }
    };
    let avatar = super::identity_avatar(
        scope,
        context.clone(),
        super::IdentityAvatarProps {
            seed: props.agent_id,
            alt_text: props.label.clone(),
            blob_ref: props.avatar_blob_ref,
            class: "avatar-img".into(),
            test_id: None,
        },
    );
    line(
        "agent-identity",
        vec![
            Box::new(
                view()
                    .class("sidebar-nav-icon contact-sidebar-agent-avatar")
                    .fill(avatar),
            ),
            paragraph(
                format!("grow truncate {}", props.label_test_id.unwrap_or_default()),
                props.label,
            ),
            paragraph(class, context.translated(scope, key)),
        ],
    )
}
