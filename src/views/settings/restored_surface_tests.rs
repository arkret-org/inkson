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
fn theme_has_one_localized_radio_group_and_reports_the_effective_system_theme() {
    let (app, context, _directory) = harness();
    app.mount(theme_page(app.scope(), context.clone())).unwrap();
    app.flush().unwrap();
    class(&app, "theme-settings");
    class(&app, "language-settings");
    class(&app, "theme-switcher");
    let radios = nodes(&app)
        .into_iter()
        .filter(|id| {
            app.tree()
                .node(*id)
                .unwrap()
                .descriptor
                .view()
                .classes
                .iter()
                .any(|value| value == "theme-switcher-option")
        })
        .collect::<Vec<_>>();
    assert_eq!(radios.len(), 3);
    let dark = radios
        .iter()
        .copied()
        .find(|id| {
            app.tree()
                .node(*id)
                .unwrap()
                .descriptor
                .view()
                .name
                .as_deref()
                == Some("Dark")
        })
        .unwrap();
    app.dispatch(dark, Event::CheckedChanged(true)).unwrap();
    app.flush().unwrap();
    assert_eq!(context.theme.get_untracked(), "night");
    assert!(
        matches!(app.tree().node(dark).unwrap().descriptor.view().props, Props::Check(value) if value.checked)
    );
    context.locale.revise(|locale| *locale = UiLocale::Zh);
    context.theme.revise(|value| *value = "system".into());
    context.system_theme_is_night.revise(|value| *value = true);
    app.flush().unwrap();
    assert_eq!(
        app.tree()
            .node(dark)
            .unwrap()
            .descriptor
            .view()
            .name
            .as_deref(),
        Some("深色")
    );
    let effective = class(&app, "theme-effective-description");
    assert!(
        matches!(app.tree().node(effective).unwrap().descriptor.view().props, Props::Text(value) if value.content.contains("深色"))
    );
    context.system_theme_is_night.revise(|value| *value = false);
    app.flush().unwrap();
    assert!(
        matches!(app.tree().node(effective).unwrap().descriptor.view().props, Props::Text(value) if value.content.contains("浅色"))
    );
    assert!(!nodes(&app).iter().any(|id| {
        app.tree()
            .node(*id)
            .unwrap()
            .descriptor
            .view()
            .classes
            .iter()
            .any(|value| value == "text-direction" || value == "settings-theme-choice")
    }));
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

#[test]
fn settings_search_disclosure_filters_on_edits_and_clears_when_closed() {
    let (app, context, _directory) = harness();
    app.mount(page(app.scope(), context, Route::Settings))
        .unwrap();
    app.flush().unwrap();
    let trigger = class(&app, "sapid-collapsible-trigger");
    assert!(!nodes(&app).iter().any(|id| {
        app.tree()
            .node(*id)
            .unwrap()
            .descriptor
            .view()
            .classes
            .iter()
            .any(|class| class == "workspace-navigation-search-input")
    }));
    app.dispatch(trigger, Event::Activate).unwrap();
    app.flush().unwrap();
    type_into(&app, "workspace-navigation-search-input", "language");
    assert!(nodes(&app).contains(&class(&app, "settings-nav-item-theme")));
    assert!(!nodes(&app).iter().any(|id| {
        app.tree()
            .node(*id)
            .unwrap()
            .descriptor
            .view()
            .classes
            .iter()
            .any(|class| class == "settings-nav-item-account")
    }));
    type_into(&app, "workspace-navigation-search-input", "no-such-control");
    class(&app, "settings-nav-empty");
    app.dispatch(trigger, Event::Activate).unwrap();
    app.flush().unwrap();
    class(&app, "settings-nav-item-account");
    class(&app, "settings-nav-item-theme");
    app.dispatch(trigger, Event::Activate).unwrap();
    app.flush().unwrap();
    assert!(
        matches!(app.tree().node(class(&app, "workspace-navigation-search-input")).unwrap().descriptor.view().props, Props::Input(value) if value.value.is_empty())
    );
    for value in ["language", ""] {
        type_into(&app, "workspace-navigation-search-input", value);
        let input = class(&app, "workspace-navigation-search-input");
        app.dispatch(
            input,
            Event::Keyboard {
                from: input,
                command: glory::render::KeyboardCommand::Dismiss,
            },
        )
        .unwrap();
        app.flush().unwrap();
        assert!(!nodes(&app).iter().any(|id| {
            app.tree()
                .node(*id)
                .unwrap()
                .descriptor
                .view()
                .classes
                .iter()
                .any(|class| class == "workspace-navigation-search-input")
        }));
        class(&app, "settings-nav-item-account");
        app.dispatch(trigger, Event::Activate).unwrap();
        app.flush().unwrap();
        assert!(
            matches!(app.tree().node(class(&app, "workspace-navigation-search-input")).unwrap().descriptor.view().props, Props::Input(value) if value.value.is_empty())
        );
    }
}
