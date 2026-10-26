use glory::render::{DismissReason, Event, NodeId, Props, Role};

use super::*;

fn nodes(app: &glory::App, class: &str) -> Vec<NodeId> {
    fn visit(tree: &glory::render::memory::Memory, id: NodeId, class: &str, out: &mut Vec<NodeId>) {
        let node = tree.node(id).unwrap();
        if node
            .descriptor
            .view()
            .classes
            .iter()
            .any(|value| value == class)
        {
            out.push(id);
        }
        for child in &node.children {
            visit(tree, *child, class, out);
        }
    }
    let tree = app.tree();
    let mut out = Vec::new();
    for root in tree.roots() {
        visit(&tree, *root, class, &mut out);
    }
    out
}
fn exercise(app: glory::App) {
    let value = app.scope().cage(Some("alpha".to_owned()));
    let enabled = app.scope().cage(true);
    let changes = app.scope().cage(Vec::<Option<String>>::new());
    app.mount(native_choice(
        app.scope(),
        NativeChoiceProps::new(
            "fixture",
            "Visibility",
            value,
            vec![
                NativeChoiceOption::new("alpha", "Alpha"),
                NativeChoiceOption::new("disabled", "Disabled").enabled(false),
                NativeChoiceOption::new("beta", "Beta"),
            ],
            move |next| {
                value.revise(|value| *value = next.clone());
                changes.revise(|changes| changes.push(next));
            },
        )
        .enabled(enabled),
    ))
    .unwrap();
    let trigger = nodes(&app, "native-choice-trigger")[0];
    assert!(app.dispatch(trigger, Event::Activate).unwrap());
    app.flush().unwrap();
    let choices = nodes(&app, "native-choice-option");
    assert_eq!(choices.len(), 3);
    assert!(!app.dispatch(choices[1], Event::Activate).unwrap());
    assert!(changes.get_untracked().is_empty());
    assert!(app.dispatch(choices[2], Event::Activate).unwrap());
    app.flush().unwrap();
    assert_eq!(value.get_untracked().as_deref(), Some("beta"));
    assert_eq!(changes.get_untracked(), vec![Some("beta".into())]);
    assert_eq!(nodes(&app, "native-choice-trigger"), vec![trigger]);
    assert!(app.dispatch(trigger, Event::Activate).unwrap());
    app.flush().unwrap();
    let panel = nodes(&app, "native-choice-panel")[0];
    {
        let tree = app.tree();
        let descriptor = tree.node(panel).unwrap().descriptor.view();
        assert_eq!(descriptor.role, Some(Role::Dialog));
        let layer = descriptor
            .semantics
            .as_ref()
            .unwrap()
            .layer
            .as_ref()
            .unwrap();
        assert!(layer.escape && layer.outside);
        assert!(layer.return_focus.is_some());
    }
    assert!(
        app.dispatch(panel, Event::Dismiss(DismissReason::Escape))
            .unwrap()
    );
    app.flush().unwrap();
    assert_eq!(nodes(&app, "native-choice-trigger"), vec![trigger]);
    assert!(app.dispatch(trigger, Event::Activate).unwrap());
    app.flush().unwrap();
    let previous_choices = nodes(&app, "native-choice-option");
    enabled.revise(|enabled| *enabled = false);
    app.flush().unwrap();
    assert!(!app.dispatch(trigger, Event::Activate).unwrap());
    assert!(!app.dispatch(previous_choices[0], Event::Activate).unwrap());
    assert_eq!(changes.get_untracked().len(), 1);
    let tree = app.tree();
    let descriptor = tree.node(trigger).unwrap().descriptor.view();
    assert_eq!(descriptor.semantics.as_ref().unwrap().expanded, Some(false));
    assert!(matches!(descriptor.props, Props::Button(_)));
}

#[test]
fn native_choice_preserves_values_permissions_dismissal_and_trigger_identity() {
    exercise(glory::App::memory());
}

#[cfg(feature = "desktop")]
#[test]
fn actual_blitz_accepts_and_operates_the_native_choice_without_select_or_menu_descriptors() {
    exercise(glory::App::new(glory::blitz::Renderer::new));
}
