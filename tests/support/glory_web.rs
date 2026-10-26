#![allow(dead_code)]
use std::rc::Rc;

use glory::Scope;
use inkson::presentation::{BootState, InksonContext, SharedStateStore};
pub fn context(scope: &Scope) -> Rc<InksonContext> {
    context_with(
        scope,
        inkson::config::LocalConfigStore::default(),
        inkson::LocalStateStore::default(),
    )
}
pub fn context_with(
    scope: &Scope,
    config_store: inkson::config::LocalConfigStore,
    store: inkson::LocalStateStore,
) -> Rc<InksonContext> {
    let config = config_store.load();
    let credential = config.session_credential.clone();
    InksonContext::new(
        scope,
        BootState {
            config_store,
            config,
            state_store: SharedStateStore::new(store),
            initial_credential: credential,
            realm_tree_nodes: vec![],
        },
        inkson::routes::Route::Dashboard,
        |_| Box::pin(std::future::pending()),
    )
}
pub fn root() -> web_sys::Element {
    let document = web_sys::window().unwrap().document().unwrap();
    let root = document.create_element("div").unwrap();
    document.body().unwrap().append_child(&root).unwrap();
    root
}
pub async fn settle() {
    gloo_timers::future::TimeoutFuture::new(35).await;
}
pub fn account(actor: &arkret_sdk::ActorId) -> inkson::config::ActiveAccountContext {
    let account = actor.as_account_id().unwrap();
    let did = account
        .principal_id
        .as_str()
        .replacen("ak:did_core:", "did:", 1);
    let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [0x71; 32],
    ));
    serde_json::from_value(serde_json::json!({"profile_id":"receipt-browser","authority":account,"principal_control_realm_id":realm,"resolution":{"did":did,"method_history_head":"head-1","version_id":"1","resolution_event_ref":"accepted-resolution","updated_at":"2026-10-20T00:00:00.000Z"},"device_id":"ak:device:01964137-0000-7000-8000-000000000001","server_url":"https://browser.example/"})).unwrap()
}
