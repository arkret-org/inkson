use super::*;

fn realm(byte: u8) -> String {
    arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [byte; 32],
    ))
    .to_string()
}
fn node(id: &str, title: &str) -> crate::models::RealmTreeNode {
    crate::models::RealmTreeNode {
        id: id.into(),
        title: title.into(),
        description: None,
        tags: Default::default(),
        public: true,
        category: None,
        direct_conversation: false,
        parent_space_id: None,
        child_space_ids: vec![],
        kind: crate::models::RealmTreeNodeKind::Realm,
        realm_id: id.into(),
    }
}
fn active_rows(app: &glory::App) -> Vec<String> {
    let tree = app.tree();
    let mut pending = tree.roots().to_vec();
    let mut active = Vec::new();
    while let Some(id) = pending.pop() {
        let node = tree.node(id).unwrap();
        let view = node.descriptor.view();
        if view.classes.iter().any(|class| class == "realm-tree-item")
            && view.classes.iter().any(|class| class == "is-active")
        {
            active.push(view.name.as_ref().unwrap().clone());
        }
        pending.extend(node.children.iter().copied());
    }
    active
}

#[test]
fn root_realm_selection_survives_history_routes_filters_control_and_respects_account_retirement() {
    let app = glory::App::memory();
    let directory = tempfile::tempdir().unwrap();
    let a = realm(0x21);
    let b = realm(0x22);
    let control = realm(0x23);
    let account =
        crate::test_support::AccountFixture::new("ak:did_core:web:selection.example").build();
    let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
    let mut snapshot = store.load();
    snapshot.realm_tree_projections.insert(control.clone(), serde_json::json!({
        "genesis": {"schema": arkret_wire::SchemaId::REALM_GENESIS_V1,
            "purpose": "principal_control", "schema_refs": [arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1]}
    }));
    store.save(snapshot);
    let context = InksonContext::new(
        app.scope(),
        BootState {
            config_store: LocalConfigStore::with_path(directory.path().join("config.json")),
            config: crate::config::ClientConfig::authenticated(account, "fixture-session".into()),
            state_store: SharedStateStore::new(store),
            initial_credential: "fixture-session".into(),
            realm_tree_nodes: vec![
                node(&a, "First"),
                node(&b, "Second"),
                node(&control, "Private control"),
            ],
        },
        Route::SettingsSection {
            section: "account".into(),
            filter: String::new(),
        },
        |_| Box::pin(std::future::pending()),
    );
    install_realm_selection(app.scope(), context.clone());
    let ui = crate::app::shell_state::ShellState::new(app.scope(), &context);
    app.mount(crate::app::sidebar::sidebar(
        app.scope(),
        context.clone(),
        ui,
    ))
    .unwrap();
    assert_eq!(active_rows(&app), vec!["First"]);
    assert!(!context.realm_events_route_enabled.get_untracked());
    context.route.revise(|route| {
        *route = Route::Realm {
            realm_id: b.clone(),
        }
    });
    app.flush().unwrap();
    assert_eq!(context.selected_realm_id.get_untracked(), b);
    assert!(context.realm_events_route_enabled.get_untracked());
    assert_eq!(active_rows(&app), vec!["Second"]);
    context.route.revise(|route| {
        *route = Route::RealmMembers {
            realm_id: b.clone(),
        }
    });
    app.flush().unwrap();
    assert!(
        context.realm_events_route_enabled.get_untracked(),
        "Members uses the real Realm event subscription"
    );
    context.route.revise(|route| {
        *route = Route::SettingsSection {
            section: "account".into(),
            filter: String::new(),
        }
    });
    app.flush().unwrap();
    assert_eq!(active_rows(&app), vec!["Second"]);
    assert!(!context.realm_events_route_enabled.get_untracked());
    context
        .selected_realm_id
        .revise(|selected| *selected = a.clone());
    app.flush().unwrap();
    assert_eq!(
        active_rows(&app),
        vec!["First"],
        "selection itself updates the sidebar outside a Realm route"
    );
    context.route.revise(|route| {
        *route = Route::Realm {
            realm_id: control.clone(),
        }
    });
    app.flush().unwrap();
    assert_eq!(context.selected_realm_id.get_untracked(), a);
    assert!(!context.realm_events_route_enabled.get_untracked());
    assert_eq!(
        active_rows(&app),
        vec!["First"],
        "private control is never a product row or remembered target"
    );
    app.scope()
        .batch(|| {
            context.account_busy.revise(|busy| *busy = true);
            context
                .account_view_retired
                .revise(|retired| *retired = true);
            context.clear_account_projections();
            context.route.revise(|route| {
                *route = Route::Realm {
                    realm_id: b.clone(),
                }
            });
        })
        .unwrap();
    app.flush().unwrap();
    assert!(context.selected_realm_id.get_untracked().is_empty());
    assert!(!context.realm_events_route_enabled.get_untracked());
    assert!(active_rows(&app).is_empty());
    app.scope()
        .batch(|| {
            context.active_account.revise(|account| *account = None);
            context
                .account_view_retired
                .revise(|retired| *retired = false);
            context.account_busy.revise(|busy| *busy = false);
        })
        .unwrap();
    app.flush().unwrap();
    assert!(!context.realm_events_route_enabled.get_untracked());
    assert!(
        context.selected_realm_id.get_untracked().is_empty(),
        "an old route cannot repopulate a signed-out account's selection"
    );
}

#[test]
fn actual_context_links_render_one_visible_label_with_their_icon() {
    let app = glory::App::memory();
    let directory = tempfile::tempdir().unwrap();
    let context = InksonContext::new(
        app.scope(),
        BootState {
            config_store: LocalConfigStore::with_path(directory.path().join("config.json")),
            config: crate::config::ClientConfig::default(),
            state_store: SharedStateStore::new(LocalStateStore::with_path(
                directory.path().join("state.json"),
            )),
            initial_credential: String::new(),
            realm_tree_nodes: vec![],
        },
        Route::KanbanRealm {
            realm_id: realm(0x24),
        },
        |_| Box::pin(std::future::pending()),
    );
    app.mount(crate::app::context_bar::context_bar(
        app.scope(),
        context,
        realm(0x24),
        Route::KanbanRealm {
            realm_id: realm(0x24),
        },
        true,
    ))
    .unwrap();
    let tree = app.tree();
    let mut pending = tree.roots().to_vec();
    let mut names = Vec::new();
    while let Some(id) = pending.pop() {
        let node = tree.node(id).unwrap();
        let descriptor = node.descriptor.view();
        if let glory::render::Props::Link(link) = descriptor.props {
            assert!(
                link.label.is_empty(),
                "filled links must not prepend a duplicate intrinsic label"
            );
            let name = descriptor.name.as_ref().unwrap();
            let mut children = node.children.iter().copied().collect::<Vec<_>>();
            let mut content = String::new();
            while let Some(id) = children.pop() {
                let child = tree.node(id).unwrap();
                if let glory::render::Props::Text(text) = child.descriptor.view().props {
                    content.push_str(&text.content);
                }
                children.extend(child.children.iter().copied());
            }
            assert_eq!(&content, name);
            names.push(name.clone());
        }
        pending.extend(node.children.iter().copied());
    }
    assert!(names.iter().any(|name| name == "Board"));
    assert!(names.iter().any(|name| name == "Members"));
}
