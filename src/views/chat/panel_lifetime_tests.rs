use std::cell::RefCell;

use super::*;

fn host() -> (glory::App, Rc<glory::core::executor::Executor>) {
    let executor = Rc::new(glory::core::executor::Executor::new(256));
    (
        glory::App::with_host(executor.clone(), glory::render::memory::Memory::new),
        executor,
    )
}
fn pump(app: &glory::App, executor: &glory::core::executor::Executor) {
    for _ in 0..32 {
        executor.poll_one();
        app.flush().unwrap();
    }
}
fn nodes(app: &glory::App, class: &str) -> Vec<glory::render::NodeId> {
    fn visit(
        app: &glory::App,
        id: glory::render::NodeId,
        class: &str,
        result: &mut Vec<glory::render::NodeId>,
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
            result.push(id);
        }
        for child in &node.children {
            visit(app, *child, class, result);
        }
    }
    let mut result = Vec::new();
    for id in app.tree().roots() {
        visit(app, *id, class, &mut result);
    }
    result
}
fn value(app: &glory::App, id: glory::render::NodeId) -> String {
    let tree = app.tree();
    let node = tree.node(id).unwrap();
    let glory::render::Props::Input(props) = node.descriptor.view().props else {
        panic!("expected actual composer input")
    };
    props.value.clone()
}
fn edit(app: &glory::App, id: glory::render::NodeId, value: &str) -> glory::ui::Result<bool> {
    let revision = {
        let tree = app.tree();
        let node = tree.node(id).unwrap();
        let glory::render::Props::Input(props) = node.descriptor.view().props else {
            panic!("expected input")
        };
        props.revision
    };
    app.dispatch(
        id,
        glory::render::Event::ValueChanged {
            value: value.into(),
            composing: false,
            revision,
        },
    )
}
fn fixture(scope: &Scope, path: &std::path::Path) -> Rc<crate::presentation::InksonContext> {
    let account = crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build();
    let mut store = LocalStateStore::with_path(path.join("state.json"));
    store.switch_active_account(&account).unwrap();
    let context = crate::presentation::InksonContext::new(
        scope,
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(path.join("config.json")),
            config: crate::config::ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(store),
            initial_credential: String::new(),
            realm_tree_nodes: Vec::new(),
        },
        Route::Dashboard,
        |_| {
            Box::pin(async {
                crate::runtime::session::CurrentSessionRefresh::retry_later(
                    "retained panel fixture",
                )
            })
        },
    );
    context
        .active_account
        .revise(|value| *value = Some(account));
    context
        .base_url
        .revise(|value| *value = "://retained-panel-fixture".into());
    context
}
fn props(suspended: Cage<bool>) -> ChatPanelProps {
    let event = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [21; 32]);
    ChatPanelProps {
        selected_realm_id: arkret_sdk::RealmId::from_event_id(&event).to_string(),
        initial_strand_id: arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [22; 32],
        ))
        .to_string(),
        embedded: true,
        source_suspended: suspended.into(),
        direct_mode: false,
        direct_peer_id: String::new(),
        sidecar_session: None,
        focus_message_id: String::new(),
        mention_insert_request: None,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_native_list_settles_under_repeated_flushes() {
    let directory = tempfile::tempdir().unwrap();
    let (app, executor) = host();
    let scope = app.scope();
    let context = fixture(scope, directory.path());
    let suspended = scope.cage(false);
    app.mount(widget(move |scope| {
        super::super::page::chat_panel(scope, context.clone(), props(suspended)).build(scope)
    }))
    .unwrap();
    pump(&app, &executor);
    let before = app.graph_stats().nodes;
    let ui_before = app.stats();
    for _ in 0..64 {
        app.flush().unwrap();
        assert_eq!(app.graph_stats().nodes, before);
        assert_eq!(app.stats().nodes, ui_before.nodes);
        assert_eq!(app.stats().owners, ui_before.owners);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_chat_panel_keeps_input_owner_draft_and_bounds_across_source_gaps() {
    let directory = tempfile::tempdir().unwrap();
    let (app, executor) = host();
    let scope = app.scope();
    let context = fixture(scope, directory.path());
    let suspended = scope.cage(false);
    let mounted_context = context.clone();
    app.mount(widget(move |scope| {
        super::super::page::chat_panel(scope, mounted_context.clone(), props(suspended))
            .build(scope)
    }))
    .unwrap();
    pump(&app, &executor);
    let input = nodes(&app, "chat-input");
    assert_eq!(input.len(), 1);
    let input = input[0];
    assert!(edit(&app, input, "unsent retained draft").unwrap());
    pump(&app, &executor);
    let before = app.graph_stats();
    let ui_before = app.stats();
    for _ in 0..8 {
        suspended.revise(|value| *value = true);
        pump(&app, &executor);
        assert_eq!(nodes(&app, "chat-input"), vec![input]);
        let surface = nodes(&app, "chat-retained-target");
        assert_eq!(surface.len(), 1);
        {
            let tree = app.tree();
            let semantics = tree
                .node(surface[0])
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap();
            assert!(semantics.hidden && semantics.inert);
        }
        let _ = edit(&app, input, "must not reach hidden composer");
        assert_eq!(value(&app, input), "unsent retained draft");
        suspended.revise(|value| *value = false);
        pump(&app, &executor);
        assert_eq!(nodes(&app, "chat-input"), vec![input]);
        assert_eq!(value(&app, input), "unsent retained draft");
        let after = app.graph_stats();
        assert_eq!(
            after.nodes, before.nodes,
            "temporary gaps must not accumulate reactive sources"
        );
        assert_eq!(
            app.stats().owners,
            ui_before.owners,
            "temporary gaps must not accumulate presentation owners"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_route_return_restores_typed_draft_and_retires_previous_input_nodes() {
    let directory = tempfile::tempdir().unwrap();
    let (app, executor) = host();
    let context = fixture(app.scope(), directory.path());
    let suspended = app.scope().cage(false);
    let mut retained_nodes = Vec::new();
    let mut ui_owners = Vec::new();
    let mut graph_nodes = Vec::new();
    for visit in 0..4 {
        let context = context.clone();
        let owner = app
            .scope()
            .mount_with(|| {
                widget(move |scope| {
                    super::super::page::chat_panel(scope, context.clone(), props(suspended))
                        .build(scope)
                })
            })
            .unwrap();
        pump(&app, &executor);
        let input = nodes(&app, "chat-input");
        assert_eq!(input.len(), 1);
        let input = input[0];
        if visit == 0 {
            assert!(edit(&app, input, "route return keeps this draft").unwrap());
        } else {
            assert_eq!(value(&app, input), "route return keeps this draft");
        }
        retained_nodes.push(input);
        ui_owners.push(app.stats().owners);
        graph_nodes.push(app.graph_stats().nodes);
        drop(owner);
        pump(&app, &executor);
        assert!(
            app.tree().node(input).is_err(),
            "retired routes must remove their real input node"
        );
    }
    assert!(
        ui_owners.windows(2).all(|pair| pair[0] == pair[1]),
        "route returns must not accumulate mounted owners"
    );
    assert!(retained_nodes.windows(2).all(|pair| pair[0] != pair[1]));
    assert!(
        graph_nodes[1..].windows(2).all(|pair| pair[0] == pair[1]),
        "after warmup, returning to the same real target must reuse common reactive state: {graph_nodes:?}"
    );
    eprintln!("chat route return graph nodes={graph_nodes:?}, presentation owners={ui_owners:?}");
}

#[test]
fn production_retained_surface_keeps_official_file_controller_and_blocks_activation() {
    let app = glory::App::memory();
    let ready = app.scope().cage(true);
    let control = app.scope().cage(None::<sapid::FileController>);
    let activations = Rc::new(RefCell::new(0usize));
    let observed = activations.clone();
    app.mount(widget(move |scope| {
        retained_surface(
            scope,
            ready,
            Box::new(
                view().fill((
                    sapid::file_button()
                        .label("Retained attachment")
                        .controller_ref(control),
                    sapid::button()
                        .label("Guarded action")
                        .class("retained-guarded-action")
                        .on_press({
                            let observed = observed.clone();
                            move || *observed.borrow_mut() += 1
                        }),
                )),
            ),
        )
        .build(scope)
    }))
    .unwrap();
    let file = control
        .get_untracked()
        .expect("official file controller mounted");
    let action = nodes(&app, "retained-guarded-action")[0];
    assert!(
        app.dispatch(action, glory::render::Event::Activate)
            .unwrap()
    );
    assert_eq!(*activations.borrow(), 1);
    ready.revise(|value| *value = false);
    app.flush().unwrap();
    assert!(file.files().try_get().is_ok());
    let _ = app.dispatch(action, glory::render::Event::Activate);
    assert_eq!(
        *activations.borrow(),
        1,
        "hidden/inert must reject programmatic activation"
    );
    ready.revise(|value| *value = true);
    app.flush().unwrap();
    assert!(file.files().try_get().is_ok());
    assert_eq!(nodes(&app, "retained-guarded-action"), vec![action]);
    assert!(
        app.dispatch(action, glory::render::Event::Activate)
            .unwrap()
    );
    assert_eq!(*activations.borrow(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn scheduled_send_readiness_gaps_keep_the_real_picker_owner_until_user_closes() {
    let directory = tempfile::tempdir().unwrap();
    let (app, executor) = host();
    let context = fixture(app.scope(), directory.path());
    let account = context.active_account.get_untracked().unwrap();
    let target = props(app.scope().cage(false));
    let open = app.scope().cage(true);
    let writable = app.scope().cage(true);
    let draft = app.scope().cage("preserved schedule body".to_owned());
    let status = app.scope().cage(String::new());
    app.mount(super::super::composer::scheduled_send_surface(
        open,
        move |scope| {
            super::super::scheduled_send_panel::scheduled_send_panel(
                scope,
                context.clone(),
                super::super::scheduled_send_panel::ScheduledSendPanelContext {
                    realm_id: target.selected_realm_id.clone(),
                    strand_id: target.initial_strand_id.clone(),
                    authority: account.authority.clone(),
                    device_id: account.device_id.clone(),
                    token: context.token,
                    draft,
                    status_msg: status,
                    writable: writable.into(),
                },
            )
        },
    ))
    .unwrap();
    pump(&app, &executor);
    let picker = nodes(&app, "scheduled-send-at-input");
    assert_eq!(picker.len(), 1);
    let owners = app.stats().owners;
    for ready in [false, true, false, true] {
        writable.revise(|value| *value = ready);
        pump(&app, &executor);
        assert_eq!(nodes(&app, "scheduled-send-at-input"), picker);
        assert_eq!(app.stats().owners, owners);
        assert_eq!(draft.get_untracked(), "preserved schedule body");
    }
    open.revise(|value| *value = false);
    pump(&app, &executor);
    assert!(nodes(&app, "scheduled-send-at-input").is_empty());
    open.revise(|value| *value = true);
    pump(&app, &executor);
    assert_ne!(nodes(&app, "scheduled-send-at-input"), picker);
}
