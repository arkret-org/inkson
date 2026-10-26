use glory::render::{Event, NodeId, Props};
use glory::ui::App;

use super::*;

pub(crate) fn harness() -> (App, Rc<InksonContext>, tempfile::TempDir) {
    let directory = tempfile::Builder::new()
        .prefix("settings-surfaces-")
        .tempdir()
        .unwrap();
    let executor = Rc::new(glory::core::executor::Executor::new(64));
    let app = App::with_host(executor, glory::render::memory::Memory::new);
    let context = InksonContext::new(
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
        Route::SettingsSection {
            section: "theme".into(),
            filter: String::new(),
        },
        |_| Box::pin(std::future::pending()),
    );
    (app, context, directory)
}
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
        .unwrap_or_else(|| panic!("missing settings class {class}"))
}
fn enabled(app: &App, id: NodeId) -> bool {
    match app.tree().node(id).unwrap().descriptor.view().props {
        Props::Button(value) => value.enabled,
        _ => panic!("real Button required"),
    }
}
fn type_into(app: &App, class_name: &str, value: &str) {
    let root = class(app, class_name);
    let input = if matches!(
        app.tree().node(root).unwrap().descriptor.view().props,
        Props::Input(_)
    ) {
        root
    } else {
        let mut pending = vec![root];
        loop {
            let id = pending.pop().expect("input descendant");
            let tree = app.tree();
            let node = tree.node(id).unwrap();
            if matches!(node.descriptor.view().props, Props::Input(_)) {
                break id;
            }
            pending.extend(node.children.iter().copied());
        }
    };
    let revision = match app.tree().node(input).unwrap().descriptor.view().props {
        Props::Input(value) => value.revision,
        _ => unreachable!(),
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
fn theme_has_separate_cards_icon_choices_current_value_switcher_and_live_direction() {
    let (app, context, _directory) = harness();
    app.mount(theme_page(app.scope(), context.clone())).unwrap();
    app.flush().unwrap();
    class(&app, "theme-settings");
    class(&app, "language-settings");
    class(&app, "theme-switcher");
    assert_eq!(
        nodes(&app)
            .iter()
            .filter(|id| app
                .tree()
                .node(**id)
                .unwrap()
                .descriptor
                .view()
                .classes
                .iter()
                .any(|value| value == "settings-theme-choice"))
            .count(),
        3
    );
    let night = class(&app, "settings-theme-night");
    app.dispatch(night, Event::Activate).unwrap();
    app.flush().unwrap();
    assert_eq!(context.theme.get_untracked(), "night");
    assert_eq!(
        app.tree()
            .node(night)
            .unwrap()
            .descriptor
            .view()
            .semantics
            .as_ref()
            .unwrap()
            .pressed,
        Some(true)
    );
    let direction = class(&app, "text-direction");
    context.locale.revise(|locale| *locale = UiLocale::Zh);
    app.flush().unwrap();
    assert_eq!(class(&app, "settings-theme-night"), night);
    assert!(
        matches!(app.tree().node(direction).unwrap().descriptor.view().props,Props::Text(value) if value.content==UiLocale::Zh.direction().as_str())
    );
    assert!(nodes(&app).iter().any(|id|matches!(app.tree().node(*id).unwrap().descriptor.view().props,Props::Text(value) if value.content==crate::i18n::tr_args("settings.theme.current",&[("theme","night".into())]))));
}

#[test]
fn actual_pair_page_restores_code_explanation_and_rejects_blank_lookup_and_resolve_inputs() {
    let (app, context, _directory) = harness();
    app.mount(devices::page(app.scope(), context.clone(), true))
        .unwrap();
    app.flush().unwrap();
    let lookup = class(&app, "accept-pairing-code-claim-button");
    let resolve = class(&app, "accept-pairing-resolve-button");
    assert!(!enabled(&app, lookup));
    assert!(!enabled(&app, resolve));
    assert!(nodes(&app).iter().any(|id|matches!(app.tree().node(*id).unwrap().descriptor.view().props,Props::Text(value) if value.content==context.tr("settings.devices.accept_code_body"))));
    type_into(&app, "accept-pairing-code-input", "   ");
    assert!(!enabled(&app, lookup));
    type_into(&app, "accept-pairing-code-input", "fixture code");
    assert!(enabled(&app, lookup));
    assert!(!enabled(&app, resolve));
    type_into(&app, "accept-pairing-input", "fixture link");
    assert!(enabled(&app, resolve));
    type_into(&app, "accept-pairing-input", "\n  ");
    assert!(!enabled(&app, resolve));
    assert_eq!(class(&app, "accept-pairing-code-claim-button"), lookup);
    assert_eq!(class(&app, "accept-pairing-resolve-button"), resolve);
}

#[test]
fn key_backup_guidance_retains_its_recovery_link_across_default_closed_reopen_and_locale_change() {
    let (app, context, _directory) = harness();
    app.mount(key_backup_guidance(app.scope(), context.clone()))
        .unwrap();
    app.flush().unwrap();
    let trigger = class(&app, "sapid-collapsible-trigger");
    let panel = class(&app, "sapid-collapsible-panel");
    let recovery = class(&app, "key-backup-open-recovery");
    let expanded = || {
        app.tree()
            .node(trigger)
            .unwrap()
            .descriptor
            .view()
            .semantics
            .as_ref()
            .unwrap()
            .expanded
    };
    let hidden = || {
        app.tree()
            .node(panel)
            .unwrap()
            .descriptor
            .view()
            .semantics
            .as_ref()
            .unwrap()
            .hidden
    };
    assert_eq!(expanded(), Some(false));
    assert!(hidden());
    for expected in [true, false, true] {
        app.dispatch(trigger, Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(expanded(), Some(expected));
        assert_eq!(hidden(), !expected);
        assert_eq!(class(&app, "key-backup-open-recovery"), recovery);
    }
    context.locale.revise(|locale| *locale = UiLocale::Zh);
    app.flush().unwrap();
    assert_eq!(class(&app, "sapid-collapsible-trigger"), trigger);
    assert_eq!(class(&app, "key-backup-open-recovery"), recovery);
    assert!(nodes(&app).iter().any(|id| matches!(
        app.tree().node(*id).unwrap().descriptor.view().props,
        Props::Text(value) if value.content == context.tr("settings.key_backup.contract")
    )));
    app.dispatch(recovery, Event::Activate).unwrap();
    app.flush().unwrap();
    assert!(matches!(
        context.route.get_untracked(),
        Route::SettingsRecovery
    ));
}

#[test]
fn settings_navigation_exposes_only_the_actual_page_as_current() {
    let (app, context, _directory) = harness();
    app.mount(page(
        app.scope(),
        context.clone(),
        Route::SettingsSection {
            section: "theme".into(),
            filter: String::new(),
        },
    ))
    .unwrap();
    app.flush().unwrap();
    for name in ["theme", "account", "storage", "recovery"] {
        let id = class(&app, &format!("settings-nav-item-{name}"));
        assert_eq!(
            app.tree()
                .node(id)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .current,
            (name == "theme").then_some(glory::render::Current::Page),
        );
    }
    context.locale.revise(|locale| *locale = UiLocale::Zh);
    app.flush().unwrap();
    assert_eq!(
        app.tree()
            .node(class(&app, "settings-nav-item-theme"))
            .unwrap()
            .descriptor
            .view()
            .semantics
            .as_ref()
            .unwrap()
            .current,
        Some(glory::render::Current::Page),
    );
}
