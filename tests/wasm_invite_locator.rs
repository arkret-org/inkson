//! Production invite controls mounted in Chrome.
#![cfg(all(target_arch = "wasm32", feature = "web"))]
use dioxus::prelude::*;
use inkson::views::settings::invite_locator::InviteLocatorCard;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

fn page() -> Element {
    let mut url = use_signal(|| "https://station.example/#token=secret".to_owned());
    let mut owned = use_signal(|| true);
    let mut busy = use_signal(|| false);
    rsx! { InviteLocatorCard {
        has_session: true, url: url(), status: String::new(), busy: busy(), has_locator: owned(),
        onrefresh: move |_| { url.set("https://station.example/#token=new".into()); owned.set(true); busy.set(true); },
        onrevoke: move |_| { url.set(String::new()); owned.set(false); },
    } }
}

#[wasm_bindgen_test(async)]
async fn browser_revoke_removes_url_qr_and_disables_revoke_then_generate_disables_both() {
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
            .query_selector("[data-testid='settings-invite-locator-url']")
            .unwrap()
            .is_some()
        {
            break;
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    let button = |id: &str| {
        root.query_selector(&format!("[data-testid='{id}']"))
            .unwrap()
            .unwrap()
            .dyn_into::<web_sys::HtmlElement>()
            .unwrap()
    };
    assert!(
        root.query_selector("[data-testid='settings-invite-locator-qr'] svg")
            .unwrap()
            .is_some()
    );
    button("settings-invite-locator-revoke").click();
    gloo_timers::future::TimeoutFuture::new(30).await;
    assert!(
        root.query_selector("[data-testid='settings-invite-locator-url-pane']")
            .unwrap()
            .is_none()
    );
    assert!(button("settings-invite-locator-revoke").has_attribute("disabled"));
    assert!(!button("settings-invite-locator-refresh").has_attribute("disabled"));
    button("settings-invite-locator-refresh").click();
    gloo_timers::future::TimeoutFuture::new(30).await;
    assert!(button("settings-invite-locator-refresh").has_attribute("disabled"));
    assert!(button("settings-invite-locator-revoke").has_attribute("disabled"));
    abort.abort();
    gloo_timers::future::TimeoutFuture::new(0).await;
    root.remove();
}
