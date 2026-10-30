//! Production picker/controller and encrypted account storage in one WASM instance.
#![cfg(all(target_arch = "wasm32", feature = "web", feature = "spec-conformance"))]

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;
use inkson::app::account_switch::{
    AccountSessionRoot, LocalStateStore, PersistedSessionGrant, SavedAccountPicker, SessionRoot,
    account_picker_options, browser_switch_grant, commit_browser_switch_storage,
    prepare_browser_switch_storage,
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
    handles: Rc<RefCell<Option<(AccountSessionRoot, SyncSignal<LocalStateStore>)>>>,
}

#[component]
fn PrivateView(store: SyncSignal<LocalStateStore>) -> Element {
    let private_text = use_signal(|| store.read().load().primary_handle);
    rsx! { p { "data-testid": "private-view", "{private_text}" } }
}

impl PartialEq for Case {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.handles, &other.handles)
    }
}

#[component]
fn Probe(case: Case, store: SyncSignal<LocalStateStore>) -> Element {
    let root = AccountSessionRoot::get();
    *case.handles.borrow_mut() = Some((root.clone(), store));
    let result = use_signal(|| "ready".to_owned());
    let drops = use_signal(|| 0_u32);
    let revision = root.revision();
    let selected = root
        .active_account()
        .map(|account| account.profile_id)
        .unwrap_or_default();
    rsx! {
        div { "data-testid": "switch-ready",
            if !root.is_switching() {
                SwitchControls { case: case.clone(), selected, result, drops }
            }
            output { "data-testid": "switch-result", "{result}" }
            output { "data-testid": "control-drops", "{drops}" }
            inkson::app::account_switch::AccountViewBoundary { revision, PrivateView { store } }
        }
    }
}

/// This component deliberately disappears during the switch. Its tasks must
/// survive under the same root lifetime used by the real account menu.
#[component]
fn SwitchControls(
    case: Case,
    selected: String,
    result: Signal<String>,
    mut drops: Signal<u32>,
) -> Element {
    use_drop(move || drops += 1);
    let choosing = AccountSessionRoot::get();
    let adding = choosing.clone();
    rsx! {
        SavedAccountPicker {
            options: account_picker_options(&case.config.load_profile_metadata().unwrap()),
            selected, busy: false,
            on_select: move |id: String| {
                choosing.clone().start_select_profile(id, move |outcome| {
                    result.set(match outcome { Ok(()) => "selected".into(), Err(error) => format!("failed: {error:#}") });
                });
            },
            on_add: move |_| {
                adding.clone().start_add_account(move |outcome| {
                    result.set(match outcome { Ok(()) => "added".into(), Err(error) => format!("failed: {error:#}") });
                });
            },
        }
    }
}

fn page(case: Case) -> Element {
    let store = use_signal_sync(|| case.store.clone());
    let config = use_signal(|| case.config.clone());
    rsx! { SessionRoot { state_store: store, config_store: Some(config), Probe { case, store } } }
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
    Rc<dioxus::core::Runtime>,
    futures_util::future::AbortHandle,
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
    let dom = VirtualDom::new_with_props(page, case.clone());
    let runtime = dom.runtime();
    let (abort, registration) = futures_util::future::AbortHandle::new_pair();
    let render_root = element.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = futures_util::future::Abortable::new(
            dioxus::web::run(dom, dioxus::web::Config::new().rootelement(render_root)),
            registration,
        )
        .await;
    });
    for _ in 0..200 {
        if element
            .query_selector("[data-testid='switch-ready']")
            .unwrap()
            .is_some()
        {
            return (element, runtime, abort, case, a, b);
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    panic!("production account picker did not mount");
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
            .query_selector("[data-testid='private-view']")
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
    let (element, runtime, abort, case, a, b) = mount("same-principal").await;
    let (root, _) = case.handles.borrow().as_ref().unwrap().clone();
    let old_generation = root.conformance_session_generation();
    let old_store = case.store.clone();
    choose(&element, &b.profile_id, "private-b").await;
    runtime.in_scope(ScopeId::ROOT, || {
        assert_eq!(root.active_account().unwrap().authority, b.authority);
        assert_eq!(
            inkson::secure_key_store::active_device_seed_scope()
                .unwrap()
                .authority,
            b.authority
        );
        assert!(!root.conformance_invalidate_session(old_generation));
        assert!(old_store.flush().is_err());
    });
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
        .query_selector("[data-testid='control-drops']")
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
    abort.abort();
    gloo_timers::future::TimeoutFuture::new(0).await;
    element.remove();
}

#[wasm_bindgen_test(async)]
async fn browser_add_account_can_return_without_promoting_pending_secrets() {
    let (element, runtime, abort, case, a, b) = mount("pending").await;
    let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
    storage
        .set_item("inkson.oidc_scaffold.v1.retired-a", "pending-transaction")
        .unwrap();
    element
        .query_selector("[data-testid='account-add']")
        .unwrap()
        .unwrap()
        .dyn_into::<web_sys::HtmlElement>()
        .unwrap()
        .click();
    for _ in 0..300 {
        if case.handles.borrow().as_ref().is_some_and(|(root, ..)| {
            runtime.in_scope(ScopeId::ROOT, || {
                root.active_account().is_none() && !root.is_switching()
            }) && element.query_selector("select").unwrap().is_some()
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
    let (_, mut pending) = case.handles.borrow().as_ref().unwrap().clone();
    runtime.in_scope(ScopeId::ROOT, || {
        pending
            .write()
            .set_session_grant(Some(grant(&b, "foreign-pending-grant")));
        pending.write().set_primary_handle("pending-b-private");
    });
    let snapshot = runtime.in_scope(ScopeId::ROOT, || pending.peek().clone());
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
    abort.abort();
    gloo_timers::future::TimeoutFuture::new(0).await;
    element.remove();
}
