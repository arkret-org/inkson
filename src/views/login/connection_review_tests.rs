use super::*;
use crate::i18n::UiLocale;

#[test]
fn production_login_mounts_and_preset_toggle_retains_the_station_input() {
    use glory::render::{Event, NodeId, Props};
    fn nodes(app: &glory::App, class: Option<&str>, input: bool) -> Vec<NodeId> {
        fn visit(
            tree: &glory::render::memory::Memory,
            id: NodeId,
            class: Option<&str>,
            input: bool,
            result: &mut Vec<NodeId>,
        ) {
            let node = tree.node(id).unwrap();
            let descriptor = node.descriptor.view();
            if class.is_some_and(|class| descriptor.classes.iter().any(|value| value == class))
                || input && matches!(descriptor.props, Props::Input(_))
            {
                result.push(id);
            }
            for child in &node.children {
                visit(tree, *child, class, input, result);
            }
        }
        let tree = app.tree();
        let mut result = Vec::new();
        for id in tree.roots() {
            visit(&tree, *id, class, input, &mut result);
        }
        result
    }
    let app = glory::App::memory();
    let directory = tempfile::tempdir().unwrap();
    let context = InksonContext::new(
        app.scope(),
        crate::presentation::BootState {
            config_store: LocalConfigStore::with_path(directory.path().join("config.json")),
            config: crate::config::ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(LocalStateStore::with_path(
                directory.path().join("state.json"),
            )),
            initial_credential: String::new(),
            realm_tree_nodes: vec![],
        },
        Route::Login,
        |_| Box::pin(std::future::pending()),
    );
    app.mount(page(app.scope(), context.clone(), Route::Login))
        .unwrap();
    app.flush().unwrap();
    let inputs = nodes(&app, None, true);
    assert_eq!(inputs.len(), 1);
    let input = inputs[0];
    let initial_toggles = nodes(&app, Some("auth-combobox-toggle"), false);
    assert_eq!(initial_toggles.len(), 1);
    let toggle = initial_toggles[0];
    {
        let tree = app.tree();
        let descriptor = tree.node(toggle).unwrap().descriptor.view();
        let Props::Button(props) = descriptor.props else {
            panic!("expected preset button")
        };
        assert!(
            props.label.is_empty(),
            "the icon-only preset trigger must not render its accessible name"
        );
        assert!(
            descriptor
                .name
                .as_ref()
                .is_some_and(|name| !name.is_empty())
        );
    }
    let revision = {
        let tree = app.tree();
        let Props::Input(props) = tree.node(input).unwrap().descriptor.view().props else {
            panic!("expected Station input")
        };
        props.revision
    };
    assert!(
        app.dispatch(
            input,
            Event::ValueChanged {
                value: "https://unsaved-station.example/".into(),
                composing: false,
                revision,
            }
        )
        .unwrap()
    );
    for open in [true, false, true, false] {
        let toggles = nodes(&app, Some("auth-combobox-toggle"), false);
        assert_eq!(toggles, vec![toggle]);
        assert!(app.dispatch(toggles[0], Event::Activate).unwrap());
        app.flush().unwrap();
        assert_eq!(
            nodes(&app, Some("auth-combobox-menu"), false).len(),
            usize::from(open)
        );
        assert_eq!(nodes(&app, None, true), vec![input]);
        let tree = app.tree();
        assert_eq!(
            tree.node(toggle)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .and_then(|semantics| semantics.expanded),
            Some(open)
        );
        let Props::Input(props) = tree.node(input).unwrap().descriptor.view().props else {
            panic!("expected retained Station input")
        };
        assert_eq!(props.value, "https://unsaved-station.example/");
    }
    let register = nodes(&app, Some("auth-create-account"), false);
    assert_eq!(register.len(), 1);
    assert!(matches!(
        app.tree()
            .node(register[0])
            .unwrap()
            .descriptor
            .view()
            .props,
        Props::Link(_)
    ));
    assert!(app.dispatch(register[0], Event::Activate).unwrap());
    assert_eq!(context.route.get_untracked(), Route::Register);
}

fn strings(app: &glory::ui::App) -> Vec<String> {
    fn visit(
        tree: &glory::render::memory::Memory,
        id: glory::render::NodeId,
        values: &mut Vec<String>,
    ) {
        let node = tree.node(id).unwrap();
        if let glory::render::Props::Text(props) = node.descriptor.view().props {
            values.push(props.content.clone());
        }
        for child in node.children.iter().copied() {
            visit(tree, child, values);
        }
    }
    let tree = app.tree();
    let mut values = Vec::new();
    for root in tree.roots() {
        visit(&tree, *root, &mut values);
    }
    values
}
#[test]
fn station_review_rerenders_retained_changes_without_translating_original_values() {
    let mut previous: arkret_sdk::StationConnectionBinding = serde_json::from_value(serde_json::json!({
            "base_url": "https://station.example/",
            "service_id": "ak:did_core:webvh:z6mkfixture",
            "trust_domain": "ak:trust_domain:station.example",
            "authentication_metadata": {
                "account_authority": { "origin": "https://auth.example", "gate_account_base_url": "https://auth.example/_arkret/gate/account" },
                "methods": [{ "method": "oidc", "issuer_uri": "https://auth.example/", "client_id": "login.connection.new", "scopes": ["openid", "profile"], "grant_exchange": { "kind": "account_handoff" } }]
            }
        })).unwrap();
    let mut second = previous.authentication_metadata.methods[0].clone();
    second.client_id = Some("unchanged-client".to_owned());
    previous.authentication_metadata.methods.push(second);
    let mut candidate = previous.clone();
    candidate.service_id = arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkchanged").unwrap();
    candidate.trust_domain =
        arkret_sdk::TrustDomainId::new("ak:trust_domain:new-station.example").unwrap();
    candidate.authentication_metadata.methods[0].client_id =
        Some("{index} {method} / 原文".to_owned());
    let change = crate::station_connection::ConnectionTrustChange {
        previous,
        candidate,
    };
    let raw_values = crate::station_connection::connection_changes(&change)
        .into_iter()
        .flat_map(|detail| [detail.previous, detail.candidate])
        .collect::<Vec<_>>();

    let app = glory::ui::App::memory();
    let directory = tempfile::tempdir().unwrap();
    let context = InksonContext::new(
        app.scope(),
        crate::presentation::BootState {
            config_store: LocalConfigStore::with_path(directory.path().join("config.json")),
            config: crate::config::ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(LocalStateStore::with_path(
                directory.path().join("state.json"),
            )),
            initial_credential: String::new(),
            realm_tree_nodes: vec![],
        },
        Route::Login,
        |_| Box::pin(async { crate::runtime::session::CurrentSessionRefresh::retry_later("test") }),
    );
    context.locale.revise(|value| *value = UiLocale::En);
    let locale = context.locale;
    let unknown = app.scope().bond({
        let context = context.clone();
        move || connection_review_field_label(&context, "future_label.{url} / 原文")
    });
    let unknown_method = app.scope().bond({
        let context = context.clone();
        move || connection_review_field_label(&context, "Sign-in method unknown (oidc)")
    });
    app.mount(glory::ui::view().fill(vec![
        connection_review_details(app.scope(), context.clone(), &change),
        plain(unknown),
        plain(unknown_method),
    ]))
    .unwrap();
    app.flush().unwrap();
    let english = strings(&app);
    assert!(
        english
            .iter()
            .any(|value| value == "Sign-in method 1 (oidc) · Client")
    );
    for language in [UiLocale::Zh, UiLocale::En] {
        locale.revise(|value| *value = language);
        app.flush().unwrap();
        let values = strings(&app);
        for raw in &raw_values {
            assert!(
                values.iter().any(|value| value == raw),
                "original trust value disappeared: {raw}"
            );
        }
        for unknown in ["future_label.{url} / 原文", "Sign-in method unknown (oidc)"] {
            assert!(values.iter().any(|value| value == unknown));
        }
        if language == UiLocale::Zh {
            for expected in [
                "服务器连接已变更",
                "服务器身份已变更",
                "信任域已变更",
                "登录提供方已变更",
                "登录方式 1（oidc） · 客户端",
                "原值",
                "新值",
                "服务器：https://station.example/",
            ] {
                assert!(
                    values.iter().any(|value| value == expected),
                    "review text missing: {expected}"
                );
            }
        } else {
            assert_eq!(values, english);
        }
    }
}
