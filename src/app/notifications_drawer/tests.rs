use glory::render::{Event, NodeId, Props, Role};

use super::*;

fn nodes(app: &glory::App) -> Vec<NodeId> {
    let tree = app.tree();
    let mut pending = tree.roots().to_vec();
    let mut nodes = Vec::new();
    while let Some(id) = pending.pop() {
        nodes.push(id);
        pending.extend(tree.node(id).unwrap().children.iter().copied());
    }
    nodes
}

fn has_class(app: &glory::App, id: NodeId, class: &str) -> bool {
    app.tree()
        .node(id)
        .unwrap()
        .descriptor
        .view()
        .classes
        .iter()
        .any(|value| value == class)
}

#[test]
fn drawer_keeps_nonmodal_hierarchy_and_closes_on_escape_settings_and_close() {
    for action in ["escape", "settings", "close"] {
        let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
        let account =
            crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build();
        context
            .state_store
            .write(|store| store.switch_active_account(&account))
            .unwrap();
        context
            .active_account
            .revise(|value| *value = Some(account));
        let open = app.scope().cage(true);
        app.mount(notifications_drawer(app.scope(), context.clone(), open))
            .unwrap();
        app.flush().unwrap();
        let panel = nodes(&app)
            .into_iter()
            .find(|id| has_class(&app, *id, "notifications-drawer-panel"))
            .unwrap();
        {
            let tree = app.tree();
            let panel_node = tree.node(panel).unwrap();
            let descriptor = panel_node.descriptor.view();
            assert_eq!(descriptor.role, Some(Role::Section));
            assert!(
                descriptor
                    .semantics
                    .as_ref()
                    .is_none_or(|semantics| semantics.layer.is_none())
            );
            assert!(panel_node.children.iter().any(|id| {
                tree.node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|class| class == "timeline")
            }));
        }
        if action == "escape" {
            app.dispatch(
                panel,
                Event::Keyboard {
                    from: panel,
                    command: glory::render::KeyboardCommand::Dismiss,
                },
            )
            .unwrap();
        } else {
            let name = context.tr(if action == "settings" {
                "notifications.tooltip.settings"
            } else {
                "common.close"
            });
            let control = nodes(&app)
                .into_iter()
                .find(|id| {
                    let tree = app.tree();
                    let descriptor = tree.node(*id).unwrap().descriptor.view();
                    descriptor.name.as_deref() == Some(name.as_str())
                        && if action == "settings" {
                            matches!(descriptor.props, Props::Link(_))
                        } else {
                            matches!(descriptor.props, Props::Button(_))
                        }
                })
                .unwrap();
            app.dispatch(control, Event::Activate).unwrap();
        }
        app.flush().unwrap();
        assert!(!open.get_untracked());
        assert!(nodes(&app).into_iter().all(|id| !has_class(
            &app,
            id,
            "notifications-drawer-panel"
        )));
        if action == "settings" {
            assert_eq!(
                context.route.get_untracked(),
                Route::SettingsSection {
                    section: "notifications".into(),
                    filter: String::new(),
                }
            );
        }
    }
}
