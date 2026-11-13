use glory::render::{Event, NodeId, Props};
use glory::ui::App;

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
        .unwrap_or_else(|| panic!("missing recovery class {class}"))
}
fn contains_text(app: &App, value: &str) -> bool {
    nodes(app).into_iter().any(|id|matches!(app.tree().node(id).unwrap().descriptor.view().props,Props::Text(text) if text.content==value))
}

#[test]
fn freshly_generated_words_keep_the_original_whitespace_contract_without_publishing_metadata() {
    let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
    app.mount(page(
        app.scope(),
        context.clone(),
        crate::routes::Route::SettingsRecovery,
    ))
    .unwrap();
    app.flush().unwrap();
    app.dispatch(class(&app, "recovery-key-regenerate"), Event::Activate)
        .unwrap();
    app.flush().unwrap();
    let raw = nodes(&app)
        .into_iter()
        .filter_map(|id| {
            let tree = app.tree();
            let view = tree.node(id).unwrap().descriptor.view();
            if view.classes.iter().any(|class| class == "rk-word")
                && let Props::Text(value) = view.props
            {
                return Some(value.content.clone());
            }
            None
        })
        .collect::<String>();
    assert_eq!(raw.split_whitespace().count(), 24);
    assert_eq!(
        nodes(&app)
            .into_iter()
            .filter(|id| app
                .tree()
                .node(*id)
                .unwrap()
                .descriptor
                .view()
                .classes
                .iter()
                .any(|class| class == "rk-word"))
            .count(),
        24
    );
    assert!(
        load_state(&context.state_store)
            .recovery_key_fingerprint
            .is_empty(),
        "generating visible words never bypasses custody confirmation or accepted publication"
    );
}

#[test]
fn established_recovery_material_shows_the_original_guard_metadata_and_closed_advanced_sections() {
    let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
    context.state_store.write(|store| {
        store.save_plain_local_data(
            super::super::RECOVERY_STATE_KEY,
            serde_json::to_string(&super::super::types::RecoveryState {
                recovery_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
                recovery_key_rotated_at: "2026-10-20T00:00:00.000Z".into(),
                ..Default::default()
            })
            .unwrap(),
        );
        crate::components::mark_mls_recovery_backup_configured(store, "fixture-accepted-backup");
    });
    app.mount(page(
        app.scope(),
        context.clone(),
        crate::routes::Route::SettingsRecovery,
    ))
    .unwrap();
    app.flush().unwrap();
    class(&app, "recovery-options");
    class(&app, "recovery-overview");
    class(&app, "recovery-key-section");
    class(&app, "recovery-key-sync-badge");
    class(&app, "recovery-key-rotation-guard");
    for key in [
        "recovery.panel.protects_title",
        "recovery.panel.protects_value",
        "recovery.panel.plaintext_cleared",
        "recovery.panel.rotation_guard_title",
        "recovery.panel.rotation_guard_body",
        "recovery.panel.last_accepted",
        "recovery.panel.fingerprint_hint",
    ] {
        assert!(
            contains_text(&app, &context.tr(key)),
            "missing original recovery copy {key}"
        );
    }
    let generate = class(&app, "recovery-key-regenerate");
    assert!(
        matches!(app.tree().node(generate).unwrap().descriptor.view().props,Props::Button(button)if!button.enabled)
    );
    let fp = class(&app, "recovery-key-fp");
    assert!(
        matches!(app.tree().node(fp).unwrap().descriptor.view().props,Props::Text(text)if text.content=="sha256:aaaaaaaaaaaa…")
    );
    for section in ["restore-section", "recovery-writeback-explainer"] {
        let root = class(&app, section);
        let tree = app.tree();
        let mut pending = vec![root];
        let trigger = loop {
            let id = pending.pop().unwrap();
            let node = tree.node(id).unwrap();
            if matches!(node.descriptor.view().props, Props::Button(_))
                && node
                    .descriptor
                    .view()
                    .semantics
                    .as_ref()
                    .is_some_and(|value| value.expanded.is_some())
            {
                break id;
            }
            pending.extend(node.children.iter().rev().copied());
        };
        drop(tree);
        assert_eq!(
            app.tree()
                .node(trigger)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .expanded,
            Some(false)
        );
        for _ in 0..3 {
            app.dispatch(trigger, Event::Activate).unwrap();
            app.flush().unwrap();
            assert_eq!(
                app.tree()
                    .node(trigger)
                    .unwrap()
                    .descriptor
                    .view()
                    .semantics
                    .as_ref()
                    .unwrap()
                    .expanded,
                Some(true)
            );
            app.dispatch(trigger, Event::Activate).unwrap();
            app.flush().unwrap();
            assert_eq!(
                app.tree()
                    .node(trigger)
                    .unwrap()
                    .descriptor
                    .view()
                    .semantics
                    .as_ref()
                    .unwrap()
                    .expanded,
                Some(false)
            );
        }
    }
    assert_eq!(class(&app, "recovery-key-regenerate"), generate);
    assert_eq!(class(&app, "recovery-key-fp"), fp);
}
