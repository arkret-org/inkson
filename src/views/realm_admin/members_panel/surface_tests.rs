use glory::render::{Event, NodeId, Props};

use super::*;

fn harness() -> (glory::App, MembersPage, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let executor = Rc::new(glory::core::executor::Executor::new(64));
    let app = glory::App::with_host(executor, glory::render::memory::Memory::new);
    let context = InksonContext::new(
        app.scope(),
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(
                directory.path().join("config.json"),
            ),
            config: crate::config::ClientConfig::default(),
            state_store: SharedStateStore::new(LocalStateStore::with_path(
                directory.path().join("state.json"),
            )),
            initial_credential: String::new(),
            realm_tree_nodes: vec![],
        },
        crate::routes::Route::Dashboard,
        |_| Box::pin(std::future::pending()),
    );
    let page = MembersPage::new(app.scope(), context, "test-realm".to_owned());
    (app, page, directory)
}

fn class_node(app: &glory::App, class: &str) -> Option<NodeId> {
    let tree = app.tree();
    let mut pending = tree.roots().to_vec();
    while let Some(id) = pending.pop() {
        let node = tree.node(id).unwrap();
        if node
            .descriptor
            .view()
            .classes
            .iter()
            .any(|value| value == class)
        {
            return Some(id);
        }
        pending.extend(node.children.iter().copied());
    }
    None
}

#[test]
fn actual_invite_cancel_and_close_are_distinct_and_preserve_the_local_target_draft() {
    let (app, page, _directory) = harness();
    let target = "https://original.example/#token=literal%20{target}%20原文";
    page.controller
        .invite_target
        .revise(|value| *value = target.to_owned());
    page.controller
        .invite_modal_open
        .revise(|value| *value = true);
    app.mount(invite_modal(app.scope(), &page)).unwrap();
    app.flush().unwrap();
    let cancel = class_node(&app, "invite-modal-cancel").unwrap();
    let close = class_node(&app, "invite-modal-close").unwrap();
    assert_ne!(cancel, close);
    assert!(matches!(
        app.tree().node(cancel).unwrap().descriptor.view().props,
        Props::Button(_)
    ));
    assert!(matches!(
        app.tree().node(close).unwrap().descriptor.view().props,
        Props::Button(_)
    ));
    app.dispatch(cancel, Event::Activate).unwrap();
    app.flush().unwrap();
    assert!(!page.controller.invite_modal_open.get_untracked());
    assert!(class_node(&app, "invite-modal-cancel").is_none());
    assert_eq!(page.controller.invite_target.get_untracked(), target);
    page.controller
        .invite_modal_open
        .revise(|value| *value = true);
    app.flush().unwrap();
    let close = class_node(&app, "invite-modal-close").unwrap();
    app.dispatch(close, Event::Activate).unwrap();
    app.flush().unwrap();
    assert!(!page.controller.invite_modal_open.get_untracked());
    assert_eq!(page.controller.invite_target.get_untracked(), target);
}

#[test]
fn member_row_description_preserves_both_complete_account_coordinates() {
    let (app, page, _directory) = harness();
    let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:original.example").unwrap();
    let station = arkret_sdk::DidCoreId::new("ak:did_core:web:another-station.example").unwrap();
    let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        principal.clone(),
        station.clone(),
    ));
    app.mount(member_row(
        app.scope(),
        &page,
        MemberGroup {
            controller: MemberProfile::bare(actor.to_string()),
            agents: vec![],
        },
        false,
        false,
        None,
    ))
    .unwrap();
    app.flush().unwrap();
    let row = class_node(&app, "member-row").unwrap();
    let identity = class_node(&app, "member-row-identity").unwrap();
    let tree = app.tree();
    let row_semantics = tree
        .node(row)
        .unwrap()
        .descriptor
        .view()
        .semantics
        .as_ref()
        .unwrap();
    let identity_node = tree.node(identity).unwrap().descriptor.view();
    assert_eq!(
        row_semantics.described_by,
        identity_node.semantics.as_ref().unwrap().id
    );
    assert!(matches!(identity_node.props, Props::Text(value)
        if value.content == format!("Principal: {principal} · Station: {station}")));
}
