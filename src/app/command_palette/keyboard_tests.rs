use glory::render::{ChoiceCommand, DismissReason, Event, NodeId, Props, Role};
use glory::ui::{App, group};

use super::*;

fn nodes(app: &App) -> Vec<NodeId> {
    let tree = app.tree();
    let mut pending = tree.roots().to_vec();
    let mut found = Vec::new();
    while let Some(id) = pending.pop() {
        found.push(id);
        pending.extend(tree.node(id).unwrap().children.iter().copied());
    }
    found
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
        _ => panic!("command input"),
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
fn mount(
    app: App,
) -> (
    App,
    std::rc::Rc<crate::presentation::InksonContext>,
    std::rc::Rc<super::super::shell_state::ShellState>,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().unwrap();
    let context = crate::presentation::InksonContext::new(
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
            realm_tree_nodes: vec![],
        },
        Route::Dashboard,
        |_| Box::pin(std::future::pending()),
    );
    let ui = super::super::shell_state::ShellState::new(app.scope(), &context);
    app.mount(group().fill((
        search_trigger(app.scope(), ui.clone()),
        command_palette(app.scope(), context.clone(), ui.clone()),
    )))
    .unwrap();
    app.flush().unwrap();
    (app, context, ui, directory)
}

fn exercise(app: App) {
    let (app, context, ui, _directory) = mount(app);
    let trigger = class(&app, "command-palette-trigger");
    app.dispatch(trigger, Event::Activate).unwrap();
    app.flush().unwrap();
    let input = class(&app, "sapid-command-search");
    change(&app, input, "demo");
    app.dispatch(
        input,
        Event::Choice {
            from: input,
            command: ChoiceCommand::Commit,
        },
    )
    .unwrap();
    app.flush().unwrap();
    assert_eq!(context.route.get_untracked(), Route::Directory);
    assert!(!ui.search_open.get_untracked());
    assert!(ui.search_query.get_untracked().is_empty());
    app.dispatch(trigger, Event::Activate).unwrap();
    app.flush().unwrap();
    change(&app, input, "unsaved query");
    app.dispatch(
        input,
        Event::Choice {
            from: input,
            command: ChoiceCommand::Close,
        },
    )
    .unwrap();
    app.flush().unwrap();
    assert!(!ui.search_open.get_untracked());
    assert!(ui.search_query.get_untracked().is_empty());
    assert_eq!(context.route.get_untracked(), Route::Directory);
}

#[test]
fn real_sapid_query_commits_directory_and_escape_clears_without_extra_navigation() {
    exercise(App::memory());
}

#[test]
fn production_sapid_destination_activates_its_current_route() {
    let (app, context, ui, _directory) = mount(App::memory());
    ui.search_open.revise(|value| *value = true);
    app.flush().unwrap();
    change(&app, class(&app, "sapid-command-search"), "Settings");
    let target = nodes(&app).into_iter().find(|id| matches!(app.tree().node(*id).unwrap().descriptor.view().props, Props::Button(button) if button.label.starts_with("Settings —"))).unwrap();
    app.dispatch(target, Event::Activate).unwrap();
    app.flush().unwrap();
    assert_eq!(context.route.get_untracked(), Route::Settings);
    assert!(!ui.search_open.get_untracked());
    assert!(ui.search_query.get_untracked().is_empty());
}

#[test]
fn sapid_command_owns_modal_focus_and_outside_dismissal() {
    let (app, _context, ui, _directory) = mount(App::memory());
    ui.search_open.revise(|value| *value = true);
    app.flush().unwrap();
    let input = class(&app, "sapid-command-search");
    let panel = class(&app, "sapid-command-dialog");
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
        assert!(layer.modal && layer.outside);
        assert_eq!(
            layer.initial_focus,
            tree.node(input)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .id
        );
    }
    app.dispatch(panel, Event::Dismiss(DismissReason::Outside))
        .unwrap();
    app.flush().unwrap();
    assert!(!ui.search_open.get_untracked());
}

#[cfg(feature = "desktop")]
#[test]
fn actual_apace_operates_the_production_sapid_command() {
    exercise(App::new(glory::apace::Renderer::new));
}
