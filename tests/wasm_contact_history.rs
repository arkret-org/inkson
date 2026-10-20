//! The production history control mounted in Chrome, including pending retry.
#![cfg(all(target_arch = "wasm32", feature = "web"))]
use dioxus::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

fn page() -> Element {
    let mut busy = use_signal(|| false);
    let mut pending = use_signal(|| false);
    rsx! { inkson::views::contacts::ContactHistoryAction {
        busy:busy(),pending:pending(),oncompact:move |_|{pending.set(true);busy.set(true);},
    } }
}

#[wasm_bindgen_test(async)]
async fn history_control_exposes_action_and_honest_pending_retry_without_double_dispatch() {
    let document = web_sys::window().unwrap().document().unwrap();
    let root = document.create_element("div").unwrap();
    document.body().unwrap().append_child(&root).unwrap();
    let render_root = root.clone();
    let (abort, registration) = futures_util::future::AbortHandle::new_pair();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = futures_util::future::Abortable::new(
            dioxus::web::run(
                VirtualDom::new(page),
                dioxus::web::Config::new().rootelement(render_root),
            ),
            registration,
        )
        .await;
    });
    for _ in 0..100 {
        if root
            .query_selector("[data-testid='contact-history-compact']")
            .unwrap()
            .is_some()
        {
            break;
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    let button = root
        .query_selector("[data-testid='contact-history-compact']")
        .unwrap()
        .unwrap()
        .dyn_into::<web_sys::HtmlElement>()
        .unwrap();
    assert!(!button.has_attribute("disabled"));
    let before = button.text_content();
    button.click();
    gloo_timers::future::TimeoutFuture::new(30).await;
    assert!(button.has_attribute("disabled"));
    assert_ne!(button.text_content(), before);
    abort.abort();
    root.remove();
}

#[cfg(feature = "spec-conformance")]
#[wasm_bindgen_test(async)]
async fn checkpoint_journal_real_indexeddb_restart_preserves_request_and_digest() {
    inkson::checkpoint_journal_browser_recovery().await;
}
