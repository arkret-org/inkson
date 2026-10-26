//! Production picker/controller and encrypted account storage in one WASM instance.
#![cfg(all(target_arch = "wasm32", feature = "web", feature = "spec-conformance"))]

use std::cell::RefCell;
use std::rc::Rc;

use glory::Scope;
use inkson::LocalStateStore;
use inkson::presentation::{SharedStateStore, View};
#[path = "support/glory_web.rs"]
mod glory_web;
use inkson::app::account_switch::{
    AccountSessionRoot, PersistedSessionGrant, account_switcher, browser_switch_grant,
    commit_browser_switch_storage, prepare_browser_switch_storage,
};
use inkson::config::{
    AccountProfile, ActiveAccountContext, ClientConfig, LocalConfigStore, MultiProfileConfig,
};
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[derive(Clone)]
struct Case {
    store: LocalStateStore,
    config: LocalConfigStore,
    handles: Rc<RefCell<Option<(AccountSessionRoot, SharedStateStore)>>>,
}
fn page(scope: &Scope, case: Case) -> View {
    use inkson::presentation::widgets::{empty, paragraph, reactive, reactive_distinct, stack};
    let context = glory_web::context_with(scope, case.config.clone(), case.store.clone());
    let root = AccountSessionRoot::from_context(context.clone());
    *case.handles.borrow_mut() = Some((root, context.state_store.clone()));
    let drops = scope.cage(0_u32);
    let controls = {
        let context = context.clone();
        reactive(context.account_busy, move |scope, busy| {
            if busy {
                return empty();
            }
            let _ = scope.on_cleanup(move || {
                let _ = drops.try_revise(|value| *value += 1);
            });
            account_switcher(scope, context.clone(), true.into())
        })
    };
    let retired = context.account_view_retired;
    let revision = context.account_revision;
    let private = {
        let context = context.clone();
        reactive_distinct(
            scope.bond(move || (revision.get(), retired.get())),
            move |scope, (_, retired)| {
                if retired {
                    return empty();
                }
                let private_text = scope.cage(
                    context
                        .state_store
                        .read(|store| store.load().primary_handle),
                );
                paragraph("private-view", private_text)
            },
        )
    };
    stack(
        "switch-ready",
        vec![
            controls,
            paragraph("control-drops", scope.bond(move || drops.get().to_string())),
            private,
        ],
    )
}

fn account(label: &str, principal: &str) -> ActiveAccountContext {
    let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [0x72; 32],
    ));
    serde_json::from_value(serde_json::json!({
        "profile_id":format!("browser-warm-{label}"),
        "authority":{"principal_id":format!("ak:did_core:web:{principal}"),"station_id":format!("ak:did_core:web:{label}.example")},
        "principal_control_realm_id":realm,
        "resolution":{"did":format!("did:web:{principal}"),"method_history_head":"head-1","version_id":"1","resolution_event_ref":"accepted-resolution","updated_at":"2026-10-20T00:00:00.000Z"},
        "device_id":"ak:device:01964137-0000-7000-8000-000000000001",
        "server_url":format!("https://{label}.example/")
    })).unwrap()
}

fn grant(account: &ActiveAccountContext, token: &str) -> PersistedSessionGrant {
    PersistedSessionGrant {
        grant_jwt: token.into(),
        session_private_key_pem: String::new(),
        grant_id: "ak:session_grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7".into(),
        audience_id: account.authority.station_id.clone(),
        granted_scope: vec![],
        account_id: account.authority.clone(),
        device_id: account.device_id.clone(),
        station_url: account.server_url.clone(),
        grant_expires_at: None,
        stored_at: chrono::Utc::now(),
    }
}

async fn mount(
    label: &str,
) -> (
    web_sys::Element,
    (),
    glory::web::WebApp,
    Case,
    ActiveAccountContext,
    ActiveAccountContext,
) {
    let keys = inkson::secure_key_store::initialize_wasm_secure_key_store_async("inkson")
        .await
        .unwrap()
        .unwrap();
    let a = account(&format!("{label}-a"), &format!("{label}-user.example"));
    let b = account(&format!("{label}-b"), &format!("{label}-user.example"));
    for (account, seed) in [(&a, [0xa; 32]), (&b, [0xb; 32])] {
        inkson::secure_key_store::UserLocalStore::new(
            account.authority.clone(),
            account.device_id.clone(),
        )
        .unwrap()
        .save_signing_seed_durable(keys.as_ref(), &seed)
        .await
        .unwrap();
    }
    let mut store = prepare_browser_switch_storage(&[a.clone(), b.clone()])
        .await
        .unwrap();
    browser_switch_grant(&a, Some(&grant(&a, "browser-grant-a")))
        .await
        .unwrap();
    browser_switch_grant(&b, Some(&grant(&b, "browser-grant-b")))
        .await
        .unwrap();
    store.switch_active_account(&a).unwrap();
    store.set_primary_handle("private-a");
    store.set_session_grant(Some(grant(&a, "browser-grant-a")));
    commit_browser_switch_storage(&store).await.unwrap();
    store.switch_active_account(&b).unwrap();
    store.set_primary_handle("private-b");
    store.set_session_grant(Some(grant(&b, "browser-grant-b")));
    commit_browser_switch_storage(&store).await.unwrap();
    store.switch_active_account(&a).unwrap();
    commit_browser_switch_storage(&store).await.unwrap();
    let mut config = LocalConfigStore::default();
    let mut profiles = MultiProfileConfig::default();
    profiles
        .upsert_and_activate(AccountProfile::new(
            a.clone(),
            "browser-credential-a".into(),
        ))
        .unwrap();
    profiles
        .upsert_and_activate(AccountProfile::new(
            b.clone(),
            "browser-credential-b".into(),
        ))
        .unwrap();
    profiles.activate(&a.profile_id);
    config.save_profiles(&profiles).unwrap();
    config.save(ClientConfig::authenticated(
        a.clone(),
        "browser-credential-a".into(),
    ));
    config.flush().unwrap();
    let case = Case {
        store,
        config,
        handles: Rc::new(RefCell::new(None)),
    };
    let document = web_sys::window().unwrap().document().unwrap();
    let element = document.create_element("div").unwrap();
    document.body().unwrap().append_child(&element).unwrap();
    let render_case = case.clone();
    let app =
        glory::web::launch_with(element.clone(), move |scope| page(scope, render_case)).unwrap();
    glory_web::settle().await;
    assert!(element.query_selector(".switch-ready").unwrap().is_some());
    (element, (), app, case, a, b)
}

async fn choose(element: &web_sys::Element, value: &str, expected: &str) {
    let select = element.query_selector("select").unwrap().unwrap();
    js_sys::Reflect::set(select.as_ref(), &"value".into(), &value.into()).unwrap();
    let event_init = web_sys::EventInit::new();
    event_init.set_bubbles(true);
    select
        .dispatch_event(&web_sys::Event::new_with_event_init_dict("change", &event_init).unwrap())
        .unwrap();
    for _ in 0..300 {
        if element
            .query_selector(".private-view")
            .unwrap()
            .unwrap()
            .text_content()
            .unwrap()
            == expected
        {
            return;
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    panic!(
        "account view did not switch to {expected}: {}",
        element.text_content().unwrap()
    );
}

#[wasm_bindgen_test(async)]
async fn browser_warm_switch_a_b_a_keeps_exact_accounts_keys_and_rejects_late_denial() {
    let (element, _, abort, case, a, b) = mount("same-principal").await;
    let (root, _) = case.handles.borrow().as_ref().unwrap().clone();
    let old_generation = root.conformance_session_generation();
    let old_store = case.store.clone();
    choose(&element, &b.profile_id, "private-b").await;
    {
        assert_eq!(root.active_account().unwrap().authority, b.authority);
        assert_eq!(
            inkson::secure_key_store::active_device_seed_scope()
                .unwrap()
                .authority,
            b.authority
        );
        assert!(!root.conformance_invalidate_session(old_generation));
        assert!(old_store.flush().is_err());
    };
    assert_eq!(
        browser_switch_grant(&b, None).await.unwrap().grant_jwt,
        "browser-grant-b"
    );
    assert!(!element.text_content().unwrap().contains("private-a"));
    assert!(!element.inner_html().contains("browser-grant"));
    assert!(!element.inner_html().contains("browser-credential"));
    choose(&element, &a.profile_id, "private-a").await;
    assert_eq!(
        LocalConfigStore::default()
            .load()
            .active_account
            .unwrap()
            .authority,
        a.authority
    );
    assert_eq!(
        browser_switch_grant(&a, None).await.unwrap().grant_jwt,
        "browser-grant-a"
    );
    let drops: u32 = element
        .query_selector(".control-drops")
        .unwrap()
        .unwrap()
        .text_content()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        drops >= 2,
        "initiating controls must unmount during both switches"
    );
    let profiles = LocalConfigStore::default().load_profiles();
    assert_eq!(
        profiles.profiles[0].session_credential,
        "browser-credential-a"
    );
    assert_eq!(
        profiles.profiles[1].session_credential,
        "browser-credential-b"
    );
    drop(abort);
    gloo_timers::future::TimeoutFuture::new(0).await;
    element.remove();
}

#[wasm_bindgen_test(async)]
async fn browser_add_account_can_return_without_promoting_pending_secrets() {
    let (element, _, abort, case, a, b) = mount("pending").await;
    let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
    storage
        .set_item("inkson.oidc_scaffold.v1.retired-a", "pending-transaction")
        .unwrap();
    element
        .query_selector(".account-picker__add")
        .unwrap()
        .unwrap()
        .dyn_into::<web_sys::HtmlElement>()
        .unwrap()
        .click();
    for _ in 0..300 {
        if case.handles.borrow().as_ref().is_some_and(|(root, ..)| {
            root.active_account().is_none()
                && !root.is_switching()
                && element.query_selector("select").unwrap().is_some()
        }) {
            break;
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    assert!(
        storage
            .get_item("inkson.oidc_scaffold.v1.retired-a")
            .unwrap()
            .is_none()
    );
    storage
        .set_item("inkson.oidc_scaffold.v1.retired-b", "pending-transaction")
        .unwrap();
    let (_, pending) = case.handles.borrow().as_ref().unwrap().clone();
    {
        pending.write(|store| store.set_session_grant(Some(grant(&b, "foreign-pending-grant"))));
        pending.write(|store| store.set_primary_handle("pending-b-private"));
    };
    let snapshot = pending.read(Clone::clone);
    commit_browser_switch_storage(&snapshot).await.unwrap();
    choose(&element, &a.profile_id, "private-a").await;
    assert!(
        storage
            .get_item("inkson.oidc_scaffold.v1.retired-b")
            .unwrap()
            .is_none()
    );
    assert!(
        !element
            .text_content()
            .unwrap()
            .contains("pending-b-private")
    );
    assert_eq!(
        browser_switch_grant(&a, None).await.unwrap().grant_jwt,
        "browser-grant-a"
    );
    drop(abort);
    gloo_timers::future::TimeoutFuture::new(0).await;
    element.remove();
}
