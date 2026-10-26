use glory::prelude::*;
use glory::render::{Event, KeyboardCommand, NodeId, Props};

use super::*;

fn nodes(app: &App) -> Vec<NodeId> {
    let tree = app.tree();
    let mut pending = tree.roots().to_vec();
    let mut nodes = vec![];
    while let Some(id) = pending.pop() {
        nodes.push(id);
        pending.extend(tree.node(id).unwrap().children.iter().copied());
    }
    nodes
}
fn class(app: &App, class: &str) -> NodeId {
    nodes(app)
        .into_iter()
        .find(|id| {
            app.tree()
                .node(*id)
                .unwrap()
                .descriptor
                .view()
                .classes
                .iter()
                .any(|value| value == class)
        })
        .unwrap()
}
fn change(app: &App, input: NodeId, value: &str) {
    let revision = match app.tree().node(input).unwrap().descriptor.view().props {
        Props::Input(value) => value.revision,
        _ => panic!("production text input"),
    };
    app.dispatch(
        input,
        Event::ValueChanged {
            value: value.into(),
            composing: false,
            revision,
        },
    )
    .unwrap();
    app.flush().unwrap();
}

#[test]
fn real_query_keyboard_submits_nonblank_directory_and_escape_clears_without_navigation() {
    let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
    let ui = super::super::shell_state::ShellState::new(app.scope(), &context);
    ui.search_open.revise(|open| *open = true);
    app.mount(group().fill((
        query_input(app.scope(), context.clone(), ui.clone()),
        command_palette(
            app.scope(),
            context.clone(),
            String::new(),
            vec![],
            ui.clone(),
        ),
    )))
    .unwrap();
    app.flush().unwrap();
    let input = class(&app, "command-query");
    let original = context.route.get_untracked();
    change(&app, input, "  ");
    app.dispatch(
        input,
        Event::Keyboard {
            from: input,
            command: KeyboardCommand::Submit,
        },
    )
    .unwrap();
    app.flush().unwrap();
    assert_eq!(context.route.get_untracked(), original);
    assert!(ui.search_open.get_untracked());
    change(&app, input, "demo");
    app.dispatch(
        input,
        Event::Keyboard {
            from: input,
            command: KeyboardCommand::Submit,
        },
    )
    .unwrap();
    app.flush().unwrap();
    assert_eq!(context.route.get_untracked(), Route::Directory);
    assert!(!ui.search_open.get_untracked());
    assert_eq!(ui.search_query.get_untracked(), "demo");
    ui.search_open.revise(|open| *open = true);
    app.dispatch(
        input,
        Event::Keyboard {
            from: input,
            command: KeyboardCommand::Dismiss,
        },
    )
    .unwrap();
    app.flush().unwrap();
    assert!(!ui.search_open.get_untracked());
    assert!(ui.search_query.get_untracked().is_empty());
    assert_eq!(context.route.get_untracked(), Route::Directory);
}

#[test]
fn production_destination_activation_and_palette_escape_clear_the_query() {
    let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
    let ui = super::super::shell_state::ShellState::new(app.scope(), &context);
    ui.search_open.revise(|open| *open = true);
    ui.search_query.revise(|query| *query = "Directory".into());
    app.mount(group().fill((
        query_input(app.scope(), context.clone(), ui.clone()),
        command_palette(
            app.scope(),
            context.clone(),
            "Directory".into(),
            vec![],
            ui.clone(),
        ),
    )))
    .unwrap();
    app.flush().unwrap();
    let item = nodes(&app)
        .into_iter()
        .find(|id| {
            app.tree()
                .node(*id)
                .unwrap()
                .descriptor
                .view()
                .name
                .as_deref()
                == Some("Navigate to Directory")
        })
        .unwrap();
    app.dispatch(item, Event::Activate).unwrap();
    app.flush().unwrap();
    assert_eq!(context.route.get_untracked(), Route::Directory);
    assert!(!ui.search_open.get_untracked());
    assert!(ui.search_query.get_untracked().is_empty());
    ui.search_open.revise(|open| *open = true);
    ui.search_query.revise(|query| *query = "stale".into());
    let close = class(&app, "command-palette-close");
    app.dispatch(
        close,
        Event::Keyboard {
            from: close,
            command: KeyboardCommand::Dismiss,
        },
    )
    .unwrap();
    app.flush().unwrap();
    assert!(!ui.search_open.get_untracked());
    assert!(ui.search_query.get_untracked().is_empty());
}

#[test]
fn command_layer_preserves_query_focus_and_closes_on_real_outside_dismissal() {
    let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
    let ui = super::super::shell_state::ShellState::new(app.scope(), &context);
    ui.search_open.revise(|open| *open = true);
    ui.search_query
        .revise(|query| *query = "unsaved query".into());
    app.mount(group().fill((
        search_trigger(app.scope(), ui.clone()),
        query_input(app.scope(), context.clone(), ui.clone()),
        command_palette(app.scope(), context, String::new(), vec![], ui.clone()),
    )))
    .unwrap();
    app.flush().unwrap();
    let query = class(&app, "command-query");
    let palette = class(&app, "command-palette");
    let trigger = nodes(&app)
        .into_iter()
        .find(|id| {
            app.tree()
                .node(*id)
                .unwrap()
                .descriptor
                .view()
                .name
                .as_deref()
                == Some("Search")
        })
        .unwrap();
    {
        let tree = app.tree();
        let query_node = tree.node(query).unwrap().descriptor.view();
        let panel = tree.node(palette).unwrap().descriptor.view();
        let query_semantics = query_node.semantics.as_ref().unwrap();
        let panel_semantics = panel.semantics.as_ref().unwrap();
        let layer = panel_semantics.layer.as_ref().unwrap();
        assert!(!layer.modal);
        assert_eq!(layer.focus, glory::render::LayerFocus::Preserve);
        assert_eq!(layer.anchor, query_semantics.id);
        assert_eq!(query_semantics.controls, panel_semantics.id);
        assert_eq!(
            tree.node(trigger)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .controls,
            panel_semantics.id
        );
        assert!(layer.outside);
        assert!(layer.initial_focus.is_none());
        assert!(layer.return_focus.is_none());
    }
    app.dispatch(
        palette,
        Event::Dismiss(glory::render::DismissReason::Outside),
    )
    .unwrap();
    app.flush().unwrap();
    assert!(!ui.search_open.get_untracked());
    assert!(ui.search_query.get_untracked().is_empty());
    app.dispatch(trigger, Event::Activate).unwrap();
    app.flush().unwrap();
    assert!(ui.search_open.get_untracked());
    app.dispatch(trigger, Event::Activate).unwrap();
    app.flush().unwrap();
    assert!(!ui.search_open.get_untracked());
}
