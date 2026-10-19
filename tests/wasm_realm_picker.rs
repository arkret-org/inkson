//! Real production preference picker mounted in Chrome.
#![cfg(all(target_arch = "wasm32", feature = "web"))]

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;
use inkson::views::settings::realm_picker::RealmPreferencePicker;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

type Options = Vec<(String, String)>;
type Handles = (Signal<Options>, Signal<String>);

#[derive(Clone)]
struct Case {
    options: Options,
    selected: String,
    handles: Rc<RefCell<Option<Handles>>>,
}

fn page(case: Case) -> Element {
    let options = use_signal(|| case.options);
    let selected = use_signal(|| case.selected);
    *case.handles.borrow_mut() = Some((options, selected));
    rsx! {
        div { "data-testid": "picker-ready",
            RealmPreferencePicker { options: options(), selected, test_id: "realm-picker" }
        }
    }
}

async fn mount(
    case: Case,
) -> (
    web_sys::Element,
    Rc<dioxus::core::Runtime>,
    futures_util::future::AbortHandle,
) {
    let document = web_sys::window().unwrap().document().unwrap();
    let root = document.create_element("div").unwrap();
    document.body().unwrap().append_child(&root).unwrap();
    let dom = VirtualDom::new_with_props(page, case);
    let runtime = dom.runtime();
    let (abort, registration) = futures_util::future::AbortHandle::new_pair();
    let render_root = root.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = futures_util::future::Abortable::new(
            dioxus::web::run(dom, dioxus::web::Config::new().rootelement(render_root)),
            registration,
        )
        .await;
    });
    for _ in 0..100 {
        if root
            .query_selector("[data-testid='picker-ready']")
            .unwrap()
            .is_some()
        {
            return (root, runtime, abort);
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    abort.abort();
    panic!("picker did not mount");
}

fn realm(byte: u8) -> String {
    arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [byte; 32],
    ))
    .to_string()
}

#[wasm_bindgen_test(async)]
async fn browser_realm_picker_empty_and_invalid_selection_have_no_fallback() {
    for (options, selected) in [
        (vec![], String::new()),
        (vec![(realm(2), "Other Realm".into())], realm(1)),
    ] {
        let handles = Rc::new(RefCell::new(None));
        let (root, _, abort) = mount(Case {
            options,
            selected,
            handles,
        })
        .await;
        let trigger = root.query_selector("button").unwrap().unwrap();
        assert!(!trigger.text_content().unwrap().contains("Other Realm"));
        abort.abort();
        gloo_timers::future::TimeoutFuture::new(0).await;
        root.remove();
    }
}

#[wasm_bindgen_test(async)]
async fn browser_realm_picker_preserves_exact_id_across_reorder_and_removal() {
    let a = realm(1);
    let b = realm(2);
    let first = format!("Engineering · {a}");
    let second = format!("Engineering · {b}");
    let handles = Rc::new(RefCell::new(None));
    let (root, runtime, abort) = mount(Case {
        options: vec![(a.clone(), first.clone()), (b.clone(), second.clone())],
        selected: a.clone(),
        handles: handles.clone(),
    })
    .await;
    assert!(root.text_content().unwrap().contains(&first));
    let (mut options, selected) = handles.borrow().unwrap();
    runtime.in_scope(ScopeId::ROOT, || {
        options.set(vec![
            (b.clone(), second.clone()),
            (a.clone(), first.clone()),
        ])
    });
    gloo_timers::future::TimeoutFuture::new(30).await;
    assert!(
        root.query_selector("button")
            .unwrap()
            .unwrap()
            .text_content()
            .unwrap()
            .contains(&first)
    );
    runtime.in_scope(ScopeId::ROOT, || {
        options.set(vec![(b.clone(), second.clone())])
    });
    gloo_timers::future::TimeoutFuture::new(30).await;
    assert!(
        !root
            .query_selector("button")
            .unwrap()
            .unwrap()
            .text_content()
            .unwrap()
            .contains("Engineering")
    );
    runtime.in_scope(ScopeId::ROOT, || assert_eq!(selected(), a));
    root.query_selector("button")
        .unwrap()
        .unwrap()
        .dyn_into::<web_sys::HtmlElement>()
        .unwrap()
        .click();
    gloo_timers::future::TimeoutFuture::new(30).await;
    let document = web_sys::window().unwrap().document().unwrap();
    // Opening the list must not assign its first selectable Realm.
    runtime.in_scope(ScopeId::ROOT, || assert_eq!(selected(), a));
    let option = document
        .query_selector(&format!("[role='option'][data-realm-id='{b}']"))
        .unwrap()
        .unwrap()
        .dyn_into::<web_sys::HtmlElement>()
        .unwrap();
    js_sys::Function::new_with_args("element", "for (const type of ['pointerdown','pointerup']) element.dispatchEvent(new PointerEvent(type,{bubbles:true,button:0,buttons:type==='pointerdown'?1:0,pointerId:1,pointerType:'mouse',clientX:1,clientY:1}));")
        .call1(&wasm_bindgen::JsValue::NULL, option.as_ref()).unwrap();
    gloo_timers::future::TimeoutFuture::new(30).await;
    runtime.in_scope(ScopeId::ROOT, || assert_eq!(selected(), b));
    abort.abort();
    gloo_timers::future::TimeoutFuture::new(0).await;
    root.remove();
}
