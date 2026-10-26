use super::*;
use crate::models::{RealmTreeNode, RealmTreeNodeKind};

fn node(id: &str, title: &str, realm: &str, parent: Option<&str>, direct: bool) -> RealmTreeNode {
    RealmTreeNode {
        id: id.into(),
        title: title.into(),
        description: None,
        tags: Default::default(),
        public: true,
        category: None,
        direct_conversation: direct,
        parent_space_id: parent.map(str::to_owned),
        child_space_ids: vec![],
        kind: if parent.is_some() {
            RealmTreeNodeKind::Space
        } else {
            RealmTreeNodeKind::Realm
        },
        realm_id: realm.into(),
    }
}

fn texts(app: &glory::ui::App) -> Vec<String> {
    fn visit(
        tree: &glory::render::memory::Memory,
        id: glory::render::NodeId,
        output: &mut Vec<String>,
    ) {
        let node = tree.node(id).unwrap();
        match node.descriptor.view().props {
            glory::render::Props::Text(props) => output.push(props.content.clone()),
            glory::render::Props::Button(props) => output.push(props.label.clone()),
            glory::render::Props::Link(props) => output.push(props.label.clone()),
            _ => {}
        }
        for child in node.children.iter() {
            visit(tree, *child, output);
        }
    }
    let tree = app.tree();
    let mut output = vec![];
    for id in tree.roots() {
        visit(&tree, *id, &mut output);
    }
    output
}

#[test]
fn nonempty_mobile_drawer_hides_control_and_direct_subtrees_before_search() {
    let app = glory::ui::App::memory();
    let directory = tempfile::tempdir().unwrap();
    let mut store = crate::state::LocalStateStore::with_path(directory.path().join("state.json"));
    // Projection inputs exercise UI visibility; no network acceptance is fabricated.
    let mut snapshot = store.load();
    snapshot.realm_tree_projections.insert("control".into(), serde_json::json!({
        "genesis": {"schema": arkret_wire::SchemaId::REALM_GENESIS_V1,
            "purpose": "principal_control", "schema_refs": [arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1]}
    }));
    store.save(snapshot);
    let nodes = vec![
        node("product", "Product Realm", "product", None, false),
        node(
            "visible-child",
            "Product Space",
            "product",
            Some("product"),
            false,
        ),
        node("control", "Private Control", "control", None, false),
        node(
            "control-child",
            "Private Control Space",
            "control",
            Some("control"),
            false,
        ),
        node("direct", "Private Direct", "direct", None, true),
        node(
            "direct-child",
            "Private Direct Space",
            "direct",
            Some("direct"),
            false,
        ),
    ];
    let context = InksonContext::new(
        app.scope(),
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(
                directory.path().join("config.json"),
            ),
            config: crate::config::ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(store),
            initial_credential: String::new(),
            realm_tree_nodes: nodes,
        },
        Route::Dashboard,
        |_| {
            Box::pin(async {
                crate::runtime::session::CurrentSessionRefresh::retry_later("fixture")
            })
        },
    );
    let ui = ShellState::new(app.scope(), &context);
    ui.mobile_open.revise(|open| *open = true);
    app.mount(mobile_drawer(app.scope(), context.clone(), ui.clone()))
        .unwrap();
    app.flush().unwrap();
    let shown = texts(&app);
    assert!(shown.iter().any(|text| text == "Product Realm"));
    assert!(shown.iter().any(|text| text == "Product Space"));
    assert!(!shown.iter().any(|text| text.starts_with("Private")));
    ui.mobile_query.revise(|query| *query = "Private".into());
    app.flush().unwrap();
    assert!(!texts(&app).iter().any(|text| text.starts_with("Private")));
    ui.mobile_query.revise(String::clear);
    app.flush().unwrap();
    assert!(texts(&app).iter().any(|text| text == "Product Realm"));
}
