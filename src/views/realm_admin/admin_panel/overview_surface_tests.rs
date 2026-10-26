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
        .unwrap_or_else(|| panic!("missing realm overview class {class}"))
}
#[test]
fn actual_overview_updates_its_member_count_without_replacing_the_metric_and_restores_security_navigation()
 {
    let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
    let realm = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    app.mount(page(
        app.scope(),
        context.clone(),
        realm.into(),
        RealmAdminSection::Overview,
    ))
    .unwrap();
    app.flush().unwrap();
    class(&app, "realm-admin-overview");
    class(&app, "realm-admin-subject-badge");
    class(&app, "settings-nav-divider");
    let count=nodes(&app).into_iter().find(|id|matches!(app.tree().node(*id).unwrap().descriptor.view().props,Props::Text(value)if value.content=="0 known")).unwrap();
    context.state_store.write(|store|store.save_realm_tree_projection(realm,serde_json::json!({"member_roster_entries":[{"actor_id":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},"membership":"join"}]})));
    context.state_revision.revise(|value| *value += 1);
    app.flush().unwrap();
    assert!(
        matches!(app.tree().node(count).unwrap().descriptor.view().props,Props::Text(value)if value.content=="1 known"),
        "real projection arrival updates the retained count rather than keeping an initial snapshot"
    );
    assert!(nodes(&app).into_iter().any(|id|matches!(app.tree().node(id).unwrap().descriptor.view().props,Props::Text(value)if value.content=="0 alerts")));
    app.dispatch(class(&app, "realm-overview-security"), Event::Activate)
        .unwrap();
    app.flush().unwrap();
    assert_eq!(
        context.route.get_untracked(),
        RealmAdminSection::Security.route(realm.into())
    );
}
