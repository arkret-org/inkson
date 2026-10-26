use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::widgets::paragraph;
use crate::presentation::{InksonContext, View};
#[derive(Clone, Default)]
pub struct SelfAttributionBadgeProps {
    pub class: Option<String>,
    pub test_id: Option<String>,
}
fn badge_class(props: SelfAttributionBadgeProps) -> String {
    format!(
        "badge self-attribution-badge {} {}",
        props.class.unwrap_or_default(),
        props.test_id.unwrap_or_default()
    )
}
#[cfg(target_arch = "wasm32")]
fn badge_target(class: String, target: sapid::FloatingTarget) -> glory::ui::Button {
    target.button(
        button()
            .class(class)
            .name("This is your account")
            .fill(text().content("ME")),
    )
}
pub fn self_attribution_badge(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: SelfAttributionBadgeProps,
) -> View {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let key = format!("self-attribution-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    let class = badge_class(props);
    #[cfg(target_arch = "wasm32")]
    {
        let _ = scope;
        Box::new(
            sapid::tooltip(key)
                .theme(context.theme_tokens())
                .label("This is your account")
                .text("This is your account")
                .target(move |target| badge_target(class.clone(), target)),
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        crate::components::native_hint(
            scope,
            context,
            key,
            "This is your account".into(),
            "This is your account".into(),
            "ME",
            class,
        )
    }
}
/// Inline counterpart for an existing action; the full account explanation remains readable.
pub fn self_attribution_badge_inline(
    _scope: &Scope,
    _context: Rc<InksonContext>,
    props: SelfAttributionBadgeProps,
) -> View {
    Box::new(group().fill((
        text().class(badge_class(props)).content("ME"),
        text().class("sr-only").content("This is your account"),
    )))
}

#[derive(Clone, Default)]
pub struct ActorIdentityLabelProps {
    pub label: String,
    pub title: Option<String>,
    pub class: Option<String>,
    pub test_id: Option<String>,
    pub self_badge_test_id: Option<String>,
    pub agent_badge_test_id: Option<String>,
    pub is_self: bool,
    pub is_agent: bool,
    pub agent_slug: Option<String>,
    pub agent_selector: Option<String>,
}
pub fn actor_identity_label(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: ActorIdentityLabelProps,
) -> View {
    let mut children = vec![paragraph("actor-identity-primary", props.label.clone())];
    if props.is_self {
        children.push(self_attribution_badge(
            scope,
            context,
            SelfAttributionBadgeProps {
                class: Some("actor-identity-self-badge".into()),
                test_id: props.self_badge_test_id,
            },
        ));
    }
    if props.is_agent || props.agent_slug.is_some_and(|slug| !slug.trim().is_empty()) {
        children.push(paragraph(
            format!(
                "badge member-badge member-badge-agent actor-identity-agent-badge {}",
                props.agent_badge_test_id.unwrap_or_default()
            ),
            "Agent",
        ));
    }
    if let Some(selector) = props
        .agent_selector
        .filter(|value| !value.trim().is_empty())
    {
        children.push(paragraph("actor-identity-selector", format!("@{selector}")));
    }
    Box::new(
        row()
            .class(format!(
                "actor-identity-label {} {}",
                props.class.unwrap_or_default(),
                props.test_id.unwrap_or_default()
            ))
            .name(props.title.unwrap_or(props.label))
            .fill(children),
    )
}

#[cfg(test)]
mod frame_tests {
    use super::*;
    #[test]
    fn real_self_badge_and_inline_action_content_are_admitted_by_memory_frame() {
        let directory = tempfile::Builder::new()
            .prefix("self-badge-")
            .tempdir_in("D:/BuildCache/inkson-glory/tmp")
            .unwrap();
        let executor = Rc::new(glory::core::executor::Executor::new(32));
        let app = App::with_host(executor, glory::render::memory::Memory::new);
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    crate::state::LocalStateStore::with_path(directory.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: Vec::new(),
            },
            crate::routes::Route::Dashboard,
            |_| Box::pin(std::future::pending()),
        );
        app.mount(
            group().fill((
                self_attribution_badge(
                    app.scope(),
                    context.clone(),
                    SelfAttributionBadgeProps::default(),
                ),
                button()
                    .name("Own agents")
                    .fill(self_attribution_badge_inline(
                        app.scope(),
                        context,
                        SelfAttributionBadgeProps::default(),
                    )),
            )),
        )
        .unwrap();
        app.flush().unwrap();
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        let mut badges = 0;
        let mut description = false;
        while let Some(id) = pending.pop() {
            let node = tree.node(id).unwrap();
            pending.extend(node.children.iter().copied());
            let view = node.descriptor.view();
            if view.classes.iter().any(|c| c == "self-attribution-badge") {
                badges += 1;
            }
            if let glory::render::Props::Text(t) = view.props {
                description |= t.content == "This is your account";
            }
        }
        assert_eq!(badges, 2);
        assert!(description);
    }
}
