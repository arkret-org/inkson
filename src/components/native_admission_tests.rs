//! Actual pinned Blitz admission and typed activation, without a GUI-hover claim.
use std::rc::Rc;

use glory::render::{DismissReason, Event, NodeId, Props, Role};

use super::*;
fn context(app: &glory::App, path: &std::path::Path) -> Rc<InksonContext> {
    InksonContext::new(
        app.scope(),
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(path.join("config.json")),
            config: crate::config::ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(
                crate::state::LocalStateStore::with_path(path.join("state.json")),
            ),
            initial_credential: String::new(),
            realm_tree_nodes: Vec::new(),
        },
        crate::routes::Route::Dashboard,
        |_| Box::pin(std::future::pending()),
    )
}
fn nodes(app: &glory::App, class: &str) -> Vec<NodeId> {
    let tree = app.tree();
    let mut pending = tree.roots().iter().rev().copied().collect::<Vec<_>>();
    let mut found = Vec::new();
    while let Some(id) = pending.pop() {
        let n = tree.node(id).unwrap();
        pending.extend(n.children.iter().rev().copied());
        if n.descriptor.view().classes.iter().any(|c| c == class) {
            found.push(id);
        }
    }
    found
}
#[test]
fn actual_blitz_accepts_help_and_me_badge_and_operates_managed_dialogs() {
    let directory = tempfile::Builder::new()
        .prefix("native-hint-")
        .tempdir_in("D:/BuildCache/inkson-glory/tmp")
        .unwrap();
    let app = glory::App::new(glory::blitz::Renderer::new);
    let context = context(&app, directory.path());
    app.mount(group().fill((
        help_tip(
            app.scope(),
            context.clone(),
            HelpTipProps {
                text: "Preserved explanation".into(),
            },
        ),
        self_attribution_badge(app.scope(), context, SelfAttributionBadgeProps::default()),
    )))
    .unwrap();
    app.flush().unwrap();
    for class in ["help-tip", "self-attribution-badge"] {
        let trigger = nodes(&app, class)[0];
        assert!(app.dispatch(trigger, Event::Activate).unwrap());
        app.flush().unwrap();
        let retained_panels = nodes(&app, "native-hint-panel");
        let panels = retained_panels
            .iter()
            .copied()
            .filter(|node| {
                let tree = app.tree();
                let view = tree.node(*node).unwrap().descriptor.view();
                view.semantics
                    .as_ref()
                    .is_some_and(|semantics| !semantics.hidden)
            })
            .collect::<Vec<_>>();
        assert_eq!(panels.len(), 1);
        let panel = panels[0];
        assert_eq!(
            app.tree().node(panel).unwrap().descriptor.view().role,
            Some(Role::Dialog)
        );
        assert!(
            app.dispatch(panel, Event::Dismiss(DismissReason::Escape))
                .unwrap()
        );
        app.flush().unwrap();
        assert_eq!(nodes(&app, class), vec![trigger]);
        assert_eq!(nodes(&app, "native-hint-panel"), retained_panels);
        for panel in retained_panels {
            let tree = app.tree();
            let view = tree.node(panel).unwrap().descriptor.view();
            assert_eq!(view.role, Some(Role::Dialog));
            assert!(view.semantics.as_ref().unwrap().hidden);
        }
    }
}
#[test]
fn actual_blitz_theme_buttons_publish_pressed_state_and_real_persist_callbacks() {
    let directory = tempfile::Builder::new()
        .prefix("native-theme-")
        .tempdir_in("D:/BuildCache/inkson-glory/tmp")
        .unwrap();
    let app = glory::App::new(glory::blitz::Renderer::new);
    let context = context(&app, directory.path());
    let theme = app.scope().cage("system".to_owned());
    let changes = app.scope().cage(Vec::<String>::new());
    app.mount(theme_switcher(
        app.scope(),
        context,
        ThemeSwitcherProps {
            theme,
            on_persist: Rc::new(move |next| changes.revise(|list| list.push(next))),
        },
    ))
    .unwrap();
    app.flush().unwrap();
    let buttons = nodes(&app, "theme-switcher-option");
    assert_eq!(buttons.len(), 3);
    for (node, label) in buttons.iter().zip(["Light", "Dark", "Follow system"]) {
        assert_eq!(
            app.tree()
                .node(*node)
                .unwrap()
                .descriptor
                .view()
                .name
                .as_deref(),
            Some(label)
        );
    }
    for (index, value) in ["light", "night", "system"].into_iter().enumerate() {
        assert!(app.dispatch(buttons[index], Event::Activate).unwrap());
        app.flush().unwrap();
        assert_eq!(theme.get_untracked(), value);
        assert_eq!(
            changes.get_untracked().last().map(String::as_str),
            Some(value)
        );
        for (candidate, node) in buttons.iter().enumerate() {
            let tree = app.tree();
            let view = tree.node(*node).unwrap().descriptor.view();
            assert!(matches!(view.props, Props::Button(_)));
            assert_eq!(
                view.semantics.as_ref().unwrap().pressed,
                Some(candidate == index)
            );
        }
    }
}
