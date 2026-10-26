use super::*;

fn fixture(app: &glory::App, path: &std::path::Path) -> Rc<InksonContext> {
    InksonContext::new(
        app.scope(),
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(path.join("config.json")),
            config: crate::config::ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(LocalStateStore::with_path(
                path.join("state.json"),
            )),
            initial_credential: String::new(),
            realm_tree_nodes: vec![],
        },
        Route::Dashboard,
        |_| Box::pin(std::future::pending()),
    )
}
fn nodes(app: &glory::App, class: &str) -> Vec<glory::render::NodeId> {
    fn visit(
        tree: &glory::render::memory::Memory,
        id: glory::render::NodeId,
        class: &str,
        result: &mut Vec<glory::render::NodeId>,
    ) {
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
            visit(tree, *child, class, result);
        }
    }
    let tree = app.tree();
    let mut result = Vec::new();
    for id in tree.roots() {
        visit(&tree, *id, class, &mut result);
    }
    result
}

#[test]
fn production_sidebar_server_button_is_admitted_and_retained_when_toggled() {
    let app = glory::App::memory();
    let dir = tempfile::tempdir().unwrap();
    let context = fixture(&app, dir.path());
    let ui = ShellState::new(app.scope(), &context);
    app.mount(sidebar(app.scope(), context, ui.clone()))
        .unwrap();
    let buttons = nodes(&app, "server-switch-button");
    assert_eq!(buttons.len(), 1);
    let button = buttons[0];
    for open in [true, false, true, false] {
        assert!(
            app.dispatch(button, glory::render::Event::Activate)
                .unwrap()
        );
        app.flush().unwrap();
        assert_eq!(ui.server_open.get_untracked(), open);
        assert_eq!(nodes(&app, "server-switch-button"), vec![button]);
    }
}

#[test]
fn production_self_row_keeps_its_button_when_owned_agents_are_collapsed() {
    let app = glory::App::memory();
    let dir = tempfile::tempdir().unwrap();
    let context = fixture(&app, dir.path());
    context
        .token
        .revise(|value| *value = "presentation-only-fixture".into());
    let ui = ShellState::new(app.scope(), &context);
    app.mount(contacts(app.scope(), context, ui.clone()))
        .unwrap();
    let buttons = nodes(&app, "contact-sidebar-user-row");
    assert_eq!(buttons.len(), 1);
    let button = buttons[0];
    for expanded in [false, true, false, true] {
        assert!(
            app.dispatch(button, glory::render::Event::Activate)
                .unwrap()
        );
        app.flush().unwrap();
        assert_eq!(ui.own_agents_expanded.get_untracked(), expanded);
        assert_eq!(nodes(&app, "contact-sidebar-user-row"), vec![button]);
    }
}

#[test]
fn production_direct_button_accepts_an_inline_generated_avatar() {
    let app = glory::App::memory();
    let dir = tempfile::tempdir().unwrap();
    let context = fixture(&app, dir.path());
    let ui = ShellState::new(app.scope(), &context);
    app.mount(direct_button(
        app.scope(),
        context,
        ui.clone(),
        "Alice".into(),
        "alice".into(),
        None,
        "peer:alice".into(),
        super::super::direct_open::DirectConversationTarget::Peer {
            peer_id: "ak:did_core:web:alice.example".into(),
        },
        None,
        false,
        "sidebar-nav-item contact-sidebar-user-row",
    ))
    .unwrap();
    app.flush().unwrap();
    let buttons = nodes(&app, "contact-sidebar-user-row");
    assert_eq!(buttons.len(), 1);
    assert_eq!(nodes(&app, "generated-avatar").len(), 1);
    ui.opening
        .revise(|value| *value = Some("peer:other".into()));
    app.flush().unwrap();
    assert_eq!(nodes(&app, "contact-sidebar-user-row"), buttons);
}

#[test]
fn direct_contact_retains_state_and_complete_recipient_identity_without_enabling_a_request() {
    use glory::render::Props;
    let app = glory::App::memory();
    let dir = tempfile::tempdir().unwrap();
    let context = fixture(&app, dir.path());
    let account = crate::test_support::authority("did:web:bob.example");
    let contact = crate::models::ContactView {
        peer: arkret_sdk::contact_operations::ContactPeer::Human {
            account_id: account.clone(),
        },
        state: arkret_sdk::ContactState::PendingIncoming,
        request_event_ref: None,
        request_message: None,
        response_event_ref: None,
        tombstone_event_ref: None,
        next_prepare_input: None,
        granted_to_peer_scopes: vec![],
        granted_by_peer_scopes: vec![],
        bidirectional_scopes: vec![arkret_sdk::contact_operations::ContactScope::DirectMessage],
        effective_scopes: None,
        direct_conversation: None,
        contact_agent_projections: vec![],
        peer_endpoint: None,
    };
    let peer = contact.peer.contact_actor_id().to_string();
    context.contact_rows.revise(|rows| *rows = vec![contact]);
    let ui = ShellState::new(app.scope(), &context);
    app.mount(direct_button(
        app.scope(),
        context.clone(),
        ui.clone(),
        "Bob".into(),
        peer.clone(),
        None,
        "contact:bob".into(),
        super::super::direct_open::DirectConversationTarget::Peer { peer_id: peer },
        None,
        false,
        "direct-conversation-row",
    ))
    .unwrap();
    let row = nodes(&app, "direct-conversation-row")[0];
    let identity = nodes(&app, "direct-recipient-identity")[0];
    let state = nodes(&app, "contact-sidebar-state")[0];
    let badge = nodes(&app, "contact-sidebar-direct-badge")[0];
    {
        let tree = app.tree();
        let row = tree.node(row).unwrap().descriptor.view();
        assert!(matches!(row.props, Props::Button(value) if value.enabled));
        let identity = tree.node(identity).unwrap().descriptor.view();
        assert_eq!(
            row.semantics.as_ref().unwrap().described_by,
            identity.semantics.as_ref().unwrap().id
        );
        assert!(
            matches!(identity.props, Props::Text(value) if value.content.contains(account.principal_id.as_str()) && value.content.contains(account.station_id.as_str()))
        );
        assert!(
            matches!(tree.node(state).unwrap().descriptor.view().props, Props::Text(value) if value.content.contains("pending"))
        );
        assert!(
            matches!(tree.node(badge).unwrap().descriptor.view().props, Props::Text(value) if value.content == context.tr("app.sidebar.direct_badge"))
        );
    }
    app.dispatch(row, glory::render::Event::Activate).unwrap();
    app.flush().unwrap();
    assert_eq!(ui.opening.get_untracked(), None);
    assert_eq!(context.route.get_untracked(), Route::Dashboard);
    ui.opening
        .revise(|value| *value = Some("other-recipient".into()));
    app.flush().unwrap();
    assert_eq!(nodes(&app, "direct-conversation-row"), vec![row]);
    assert!(
        matches!(app.tree().node(row).unwrap().descriptor.view().props, Props::Button(value) if !value.enabled)
    );
}
