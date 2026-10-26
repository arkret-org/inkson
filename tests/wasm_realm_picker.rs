//! The production controlled preference picker mounted in a browser.
#![cfg(all(target_arch = "wasm32", feature = "web"))]
use std::cell::RefCell;
use std::rc::Rc;

use glory::Cage;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;
#[path = "support/glory_web.rs"]
mod glory_web;
wasm_bindgen_test_configure!(run_in_browser);
type Options = Vec<(String, String)>;
type Handles = (Cage<Options>, Cage<String>);
fn realm(byte: u8) -> String {
    arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [byte; 32],
    ))
    .to_string()
}
fn mount(options: Options, selected: String) -> (web_sys::Element, glory::web::WebApp, Handles) {
    let root = glory_web::root();
    let handles = Rc::new(RefCell::new(None));
    let mounted = handles.clone();
    let app = glory::web::launch_with(root.clone(), move |scope| {
        let context = glory_web::context(scope);
        let options = scope.cage(options);
        let selected = scope.cage(selected);
        *mounted.borrow_mut() = Some((options, selected));
        inkson::views::settings::realm_picker::realm_preference_picker(
            scope,
            context,
            options.into(),
            selected,
            "realm-picker",
        )
    })
    .unwrap();
    let handles = handles.borrow().unwrap();
    (root, app, handles)
}
#[wasm_bindgen_test(async)]
async fn browser_realm_picker_empty_and_invalid_selection_have_no_fallback() {
    for (options, selected) in [
        (vec![], String::new()),
        (vec![(realm(2), "Other Realm".into())], realm(1)),
    ] {
        let (root, app, _) = mount(options, selected);
        glory_web::settle().await;
        let trigger = root.query_selector("button").unwrap().unwrap();
        assert!(!trigger.text_content().unwrap().contains("Other Realm"));
        drop(app);
        root.remove();
    }
}
#[wasm_bindgen_test(async)]
async fn browser_realm_picker_preserves_exact_id_across_reorder_and_removal() {
    let a = realm(1);
    let b = realm(2);
    let first = format!("Engineering · {a}");
    let second = format!("Engineering · {b}");
    let (root, app, (options, selected)) = mount(
        vec![(a.clone(), first.clone()), (b.clone(), second.clone())],
        a.clone(),
    );
    glory_web::settle().await;
    assert!(root.text_content().unwrap().contains(&first));
    options.revise(|value| *value = vec![(b.clone(), second.clone()), (a.clone(), first.clone())]);
    app.app().flush().unwrap();
    glory_web::settle().await;
    assert!(
        root.query_selector("button")
            .unwrap()
            .unwrap()
            .text_content()
            .unwrap()
            .contains(&first)
    );
    options.revise(|value| *value = vec![(b.clone(), second.clone())]);
    app.app().flush().unwrap();
    glory_web::settle().await;
    assert!(
        !root
            .query_selector("button")
            .unwrap()
            .unwrap()
            .text_content()
            .unwrap()
            .contains("Engineering")
    );
    assert_eq!(selected.get_untracked(), a);
    root.query_selector("button")
        .unwrap()
        .unwrap()
        .dyn_into::<web_sys::HtmlElement>()
        .unwrap()
        .click();
    glory_web::settle().await;
    assert_eq!(
        selected.get_untracked(),
        a,
        "opening never assigns the first Realm"
    );
    let options = root.query_selector_all("[role='option']").unwrap();
    let option = (0..options.length())
        .find_map(|index| {
            let option = options.item(index)?.dyn_into::<web_sys::Element>().ok()?;
            option
                .text_content()
                .unwrap_or_default()
                .contains(&second)
                .then_some(option)
        })
        .expect("the exact remaining Realm is offered alongside the explicit empty choice");
    option.dyn_into::<web_sys::HtmlElement>().unwrap().click();
    glory_web::settle().await;
    assert_eq!(selected.get_untracked(), b);
    drop(app);
    root.remove();
}
