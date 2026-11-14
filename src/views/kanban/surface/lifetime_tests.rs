use glory::prelude::{Widget, widget};

use super::*;

fn nodes(app: &glory::App, class: &str) -> Vec<glory::render::NodeId> {
    fn visit(
        app: &glory::App,
        id: glory::render::NodeId,
        class: &str,
        found: &mut Vec<glory::render::NodeId>,
    ) {
        let tree = app.tree();
        let node = tree.node(id).unwrap();
        if node
            .descriptor
            .view()
            .classes
            .iter()
            .any(|value| value == class)
        {
            found.push(id);
        }
        for child in &node.children {
            visit(app, *child, class, found);
        }
    }
    let mut found = Vec::new();
    for root in app.tree().roots() {
        visit(app, *root, class, &mut found);
    }
    found
}

fn pump(app: &glory::App, executor: &glory::core::executor::Executor) {
    for _ in 0..32 {
        executor.poll_one();
        app.flush().unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_card_updates_keep_the_open_card_composer_and_save_button() {
    let directory = tempfile::tempdir().unwrap();
    let executor = Rc::new(glory::core::executor::Executor::new(256));
    let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    let scope = app.scope();
    let account = crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build();
    let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
    store.switch_active_account(&account).unwrap();
    let context = InksonContext::new(
        scope,
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(
                directory.path().join("config.json"),
            ),
            config: crate::config::ClientConfig::default(),
            state_store: SharedStateStore::new(store),
            initial_credential: String::new(),
            realm_tree_nodes: Vec::new(),
        },
        Route::Kanban,
        |_| {
            Box::pin(async {
                crate::runtime::session::CurrentSessionRefresh::retry_later("card composer fixture")
            })
        },
    );
    context
        .active_account
        .revise(|value| *value = Some(account.clone()));
    let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [31; 32],
    ))
    .to_string();
    let board_id = arkret_sdk::SpaceId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [32; 32],
    ));
    let column_id = arkret_sdk::SpaceId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [33; 32],
    ))
    .to_string();
    let controller = new_kanban_controller(scope, &Route::Kanban, Vec::new(), Some(board_id));
    controller
        .adding_card_to
        .revise(|value| *value = Some(column_id.clone()));
    controller
        .new_card_title
        .revise(|value| *value = "next unsent card".into());
    let columns = scope.cage(vec![KanbanColumn {
        id: column_id,
        title: "Backlog".into(),
        rank: "a".into(),
        cards: Vec::new(),
        state: SpaceContainerLifecycleState::Active,
    }]);
    let write_ready = scope.cage(true);
    let board = Board {
        app: context,
        controller,
        realm: realm.clone(),
        local_realm: realm,
        projection_realm: String::new(),
        principal: account.principal_id().clone(),
        authority: account.authority.clone(),
        device: account.device_id,
        columns: scope.bond(move || columns.get()),
        security: scope.bond(|| Some(false)),
        ready: scope.bond(move || write_ready.get()),
        synthesis: scope.bond(Vec::new),
        page: scope.cage(0),
    };
    app.mount(widget(move |scope| {
        board_allowed(scope, board.clone()).build(scope)
    }))
    .unwrap();
    pump(&app, &executor);
    let disclosure = nodes(&app, "board-toolbar-add-list")[0];
    let trigger = {
        let tree = app.tree();
        tree.node(disclosure)
            .unwrap()
            .children
            .iter()
            .copied()
            .find(|id| {
                tree.node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|class| class == "sapid-collapsible-trigger")
            })
            .expect("the real List disclosure trigger")
    };
    assert!(
        app.dispatch(trigger, glory::render::Event::Activate)
            .unwrap()
    );
    pump(&app, &executor);
    let list_input = nodes(&app, "new-column-input")[0];
    write_ready.revise(|ready| *ready = false);
    pump(&app, &executor);
    let revision = {
        let tree = app.tree();
        let glory::render::Props::Input(props) =
            tree.node(list_input).unwrap().descriptor.view().props
        else {
            panic!("real List draft input")
        };
        assert!(
            props.enabled,
            "current refresh pauses submission, not local draft input"
        );
        props.revision
    };
    app.dispatch(
        list_input,
        glory::render::Event::ValueChanged {
            value: "Next local List".into(),
            composing: false,
            revision,
        },
    )
    .unwrap();
    pump(&app, &executor);
    assert_eq!(
        controller.new_column_title.get_untracked(),
        "Next local List"
    );
    assert!(
        app.dispatch(trigger, glory::render::Event::Activate)
            .unwrap()
    );
    pump(&app, &executor);
    assert!(
        app.dispatch(trigger, glory::render::Event::Activate)
            .unwrap()
    );
    pump(&app, &executor);
    assert_eq!(nodes(&app, "new-column-input"), vec![list_input]);
    let submit = nodes(&app, "add-column-button")[0];
    {
        let tree = app.tree();
        let glory::render::Props::Button(button) =
            tree.node(submit).unwrap().descriptor.view().props
        else {
            panic!("real List submit control")
        };
        assert!(
            !button.enabled,
            "the current authority gate still blocks submission"
        );
    }
    write_ready.revise(|ready| *ready = true);
    pump(&app, &executor);
    assert_eq!(nodes(&app, "new-column-input"), vec![list_input]);
    assert_eq!(
        controller.new_column_title.get_untracked(),
        "Next local List"
    );
    let input = nodes(&app, "new-card-title-input");
    let save = nodes(&app, "save-card-button");
    assert_eq!(input.len(), 1);
    assert_eq!(save.len(), 1);
    let mut card = seed_columns().remove(0).cards.remove(0);
    card.id = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [34; 32],
    ))
    .to_string();
    columns.revise(|value| value[0].cards.push(card));
    pump(&app, &executor);
    assert_eq!(
        nodes(&app, "new-card-title-input"),
        input,
        "a background card must not retire the user's active input"
    );
    assert_eq!(
        nodes(&app, "save-card-button"),
        save,
        "the next user activation keeps its actual Save handler"
    );
    assert_eq!(nodes(&app, "kanban-card").len(), 1);
    {
        let tree = app.tree();
        let node = tree.node(input[0]).unwrap();
        let glory::render::Props::Input(props) = node.descriptor.view().props else {
            panic!("expected the real card composer")
        };
        assert_eq!(props.value, "next unsent card");
    }
    columns.revise(|value| {
        let mut other = value[0].clone();
        other.id = arkret_sdk::SpaceId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [35; 32],
        ))
        .to_string();
        other.cards.clear();
        value.push(other);
    });
    pump(&app, &executor);
    let order = nodes(&app, "kanban-column");
    columns.revise(|value| value.reverse());
    pump(&app, &executor);
    assert_eq!(
        nodes(&app, "kanban-column"),
        order.into_iter().rev().collect::<Vec<_>>()
    );
    assert_eq!(nodes(&app, "new-card-title-input"), input);
    columns.revise(|value| value.reverse());
    pump(&app, &executor);
    let title = nodes(&app, "kanban-column-title")[0];
    assert!(app.dispatch(title, glory::render::Event::Activate).unwrap());
    pump(&app, &executor);
    let rename = nodes(&app, "column-rename-input");
    assert_eq!(rename.len(), 1);
    let graph_nodes = app.graph_stats().nodes;
    let owners = app.stats().owners;
    for update in 0..32 {
        columns.revise(|value| value[0].cards[0].title = format!("Accepted card update {update}"));
        pump(&app, &executor);
        assert_eq!(nodes(&app, "new-card-title-input"), input);
        assert_eq!(nodes(&app, "save-card-button"), save);
        assert_eq!(nodes(&app, "column-rename-input"), rename);
        assert_eq!(app.stats().owners, owners);
        assert_eq!(app.graph_stats().nodes, graph_nodes);
    }
    columns.revise(|value| value[0].state = SpaceContainerLifecycleState::Archived);
    pump(&app, &executor);
    assert!(nodes(&app, "new-card-title-input").is_empty());
    assert!(app.tree().node(input[0]).is_err());
    assert!(app.tree().node(save[0]).is_err());
}
